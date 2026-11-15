package com.example.pinvault.loadtest

import com.example.pinvault.server.service.attestation.AttestationService
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.longOrNull
import kotlinx.serialization.json.put
import okhttp3.Call
import okhttp3.Callback
import okhttp3.ConnectionPool
import okhttp3.Dispatcher
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import org.HdrHistogram.Histogram
import org.HdrHistogram.Recorder
import java.io.File
import java.io.IOException
import java.lang.management.ManagementFactory
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.Signature
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.util.Base64
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.LongAdder
import java.util.concurrent.locks.LockSupport
import javax.net.ssl.SSLContext
import javax.net.ssl.X509TrustManager
import kotlin.math.max

/*
 * Open-loop load generator for one PinVault server (loadtest/README.md).
 *
 *   keys  --devices N --keys FILE                       make N device keys (P-256) and ids
 *   run   --target URL --keys FILE --rate R --duration S [knobs]
 *
 * A "round" is what the library does every attestIntervalSeconds:
 * GET /api/v1/attest/challenge, sign the canonical string with the device
 * key, POST /api/v1/attest; it counts as ok only for result=pass with a token.
 * Rounds (and config fetches, --mix) start on a fixed schedule whatever the
 * server does (open loop); latency is measured from the scheduled start, so a
 * slow server shows up as latency, not as a lower offered rate.
 */

private val json = Json { ignoreUnknownKeys = true }

fun main(args: Array<String>) {
    val cmd = args.firstOrNull() ?: usage()
    val opts = Opts(args.drop(1))
    when (cmd) {
        "keys" -> makeKeys(opts.int("devices", 1000), File(opts.str("keys", "loadtest-keys.txt")))
        "run" -> Run(opts).start()
        "seed" -> seed(opts)
        else -> usage()
    }
}

private fun usage(): Nothing {
    System.err.println("usage: keys --devices N --keys FILE | run --target URL --keys FILE --rate R --duration S [see loadtest/README.md]")
    kotlin.system.exitProcess(2)
}

class Opts(args: List<String>) {
    private val map = args.chunked(2).associate { (k, v) -> k.removePrefix("--") to v }
    fun str(name: String, default: String) = map[name] ?: default
    fun strOrNull(name: String) = map[name]
    fun int(name: String, default: Int) = map[name]?.toInt() ?: default
    fun double(name: String, default: Double) = map[name]?.toDouble() ?: default
    fun bool(name: String, default: Boolean) = map[name]?.toBooleanStrict() ?: default
}

// ── Devices ──────────────────────────────────────────────────────────────

class Device(val id: String, val key: PrivateKey, val spkiBase64: String) {
    /** What the device holds (from the last embedded config): sent back so the server does not embed it again. */
    @Volatile var configVersion: Int? = null
    @Volatile var configIssuedAt: Long? = null
}

fun makeKeys(n: Int, file: File) {
    val lines = arrayOfNulls<String>(n)
    val pool = Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors())
    val enc = Base64.getEncoder()
    val salt = java.util.UUID.randomUUID().toString().take(8)
    (0 until n).map { i ->
        pool.submit {
            val kp = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
            lines[i] = "lt-$salt-%07d ${enc.encodeToString(kp.private.encoded)} ${enc.encodeToString(kp.public.encoded)}".format(i)
        }
    }.forEach { it.get() }
    pool.shutdown()
    file.writeText(lines.joinToString("\n", postfix = "\n"))
    println("wrote $n device keys to $file")
}

fun loadDevices(file: File, limit: Int, offset: Int = 0): List<Device> {
    val kf = KeyFactory.getInstance("EC")
    val dec = Base64.getDecoder()
    return file.useLines { lines ->
        lines.filter { it.isNotBlank() }.drop(offset).take(if (limit > 0) limit else Int.MAX_VALUE).map { line ->
            val (id, pkcs8, spki) = line.trim().split(' ')
            Device(id, kf.generatePrivate(PKCS8EncodedKeySpec(dec.decode(pkcs8))), spki)
        }.toList()
    }
}

// ── What the library sends ──────────────────────────────────────────────

/** The sample app's package and signer (the server's own test constants: TestAttestationChains). */
const val PACKAGE = "com.example.sampleclient"
val SIGNER_COLONS: String = (0 until 32).joinToString(":") { "%02x".format((it * 7) and 0xFF) }
const val FEATURES = "redelivery,multisig,keyset"
private val SIGNALS = listOf("rooted", "emulator", "debugger", "debuggable", "hooking_framework", "app_integrity", "cloner",
    "unknown_installer", "adb_enabled", "software_key", "key_unattested", "old_patch_level")
private val SIGNALS_JSON = SIGNALS.joinToString(",") { "\"$it\":{\"flag\":false,\"evidence\":[]}" }

/** A clean Android report (ATTESTATION.md §3), shaped like the library's; keyAttested false: no chain is sent (README). */
fun report(now: Long): String =
    """{"sdkVersion":"2.9.1","reportTime":$now,""" +
        """"app":{"packageName":"$PACKAGE","versionCode":412,"versionName":"4.1.2","signerSha256":["$SIGNER_COLONS"],"installer":"com.android.vending","debuggable":false},""" +
        """"device":{"manufacturer":"Google","model":"Pixel 8","brand":"google","device":"shiba","product":"shiba","hardware":"shiba",""" +
        """"fingerprint":"google/shiba/shiba:15/AP4A.250105.002/12701944:user/release-keys","sdkInt":35,"securityPatch":"2026-09-05",""" +
        """"verifiedBootState":"green","keySecurityLevel":"strongbox","keyAttested":false},""" +
        """"signals":{$SIGNALS_JSON}}"""

private val signers = ThreadLocal.withInitial { Signature.getInstance("SHA256withECDSA") }

fun sign(key: PrivateKey, text: String): String = signers.get().run {
    initSign(key); update(text.toByteArray(Charsets.UTF_8)); Base64.getEncoder().encodeToString(sign())
}

fun attestBody(device: Device, nonce: String, hosts: List<String>?): String {
    val report = report(System.currentTimeMillis())
    return buildJsonObject {
        put("v", 1)
        put("nonce", nonce)
        put("deviceId", device.id)
        put("publicKey", device.spkiBase64)
        put("report", report)
        // The server's own canonical string (ATTESTATION.md §2.2): what it verifies is what is signed here.
        put("signature", sign(device.key, AttestationService.canonical(nonce, device.id, report)))
        device.configVersion?.let { put("currentConfigVersion", it) }
        device.configIssuedAt?.let { put("currentIssuedAt", it) }
        hosts?.let { h -> put("hosts", kotlinx.serialization.json.buildJsonArray { h.forEach { add(JsonPrimitive(it)) } }) }
    }.toString()
}

// ── Measurement ──────────────────────────────────────────────────────────

class Op(val name: String) {
    val recorder = Recorder(3_600_000_000L, 3) // µs, up to an hour
    val total = Histogram(3_600_000_000L, 3)
    val ok = LongAdder()
    val err = LongAdder()
    val okInterval = LongAdder()
    val errInterval = LongAdder()
    fun record(startNanos: Long) = recorder.recordValue(max(1, (System.nanoTime() - startNanos) / 1000))
}

class Run(private val o: Opts) {
    private val target = o.str("target", "https://127.0.0.1:7301").trimEnd('/')
    private val rate = o.double("rate", 10.0)
    private val duration = o.int("duration", 30)
    private val warmup = o.int("warmup", 0)
    private val reportEvery = o.int("report-every", 10)
    private val conn = o.str("conn", "per-round") // per-round | pooled
    private val tlsResume = o.bool("tls-resume", false)
    private val maxInflight = o.int("max-inflight", 4000)
    private val label = o.str("label", "run")
    private val out = o.strOrNull("out")?.let(::File)
    private val narrowHosts = o.str("hosts", "api.example.com,cdn.example.com").split(',')
    /** Shares of the schedule: attest (a round), config-full (GET, no scoping), config-narrow (GET ?hosts= + X-Device-Id). */
    private val mix: List<Pair<String, Double>> = o.str("mix", "attest=1").split(',').map { part ->
        val (k, v) = part.split('='); k.trim() to v.toDouble()
    }.also { m -> require(m.all { it.first in setOf("attest", "attest-narrow", "config-full", "config-narrow") }) { "unknown mix entry in $m" } }
    private val devices = loadDevices(File(o.str("keys", "loadtest-keys.txt")), o.int("devices", 0), o.int("offset", 0))

    private val ops = ConcurrentHashMap<String, Op>()
    private fun op(name: String) = ops.computeIfAbsent(name) { Op(it) }
    private val errors = ConcurrentHashMap<String, LongAdder>()
    private val protocols = ConcurrentHashMap<String, LongAdder>()
    private val inflight = AtomicInteger()
    private val maxInflightSeen = AtomicInteger()
    private val lagMaxMicros = AtomicLong()
    private val nextDevice = AtomicInteger()
    @Volatile private var measuring = warmup == 0

    private val trustAll = object : X509TrustManager {
        override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
        override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
        override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
    }
    private fun sslContext(): SSLContext = SSLContext.getInstance("TLS").apply { init(null, arrayOf(trustAll), SecureRandom()) }
    private val sharedSsl = sslContext()

    private val base: OkHttpClient = OkHttpClient.Builder()
        .dispatcher(Dispatcher(Executors.newCachedThreadPool { r -> Thread(r, "lt-http").apply { isDaemon = true } }).apply {
            maxRequests = 100_000; maxRequestsPerHost = 100_000
        })
        .sslSocketFactory(sharedSsl.socketFactory, trustAll)
        .hostnameVerifier { _, _ -> true } // a load test against 127.0.0.1 and the server's own certificate
        .connectTimeout(10, TimeUnit.SECONDS).readTimeout(30, TimeUnit.SECONDS).callTimeout(60, TimeUnit.SECONDS)
        .retryOnConnectionFailure(false)
        .apply {
            if (conn == "pooled") {
                // HTTP/1.1 so the pool opens a connection per concurrent call (h2 would multiplex them all on one socket).
                protocols(listOf(Protocol.HTTP_1_1)); connectionPool(ConnectionPool(1000, 5, TimeUnit.MINUTES))
            }
        }
        .build()

    /** The client for one round: pooled = the shared one; per-round = its own connection (and TLS session unless --tls-resume). */
    private fun clientForRound(): OkHttpClient = if (conn == "pooled") base else base.newBuilder()
        .connectionPool(ConnectionPool(1, 1, TimeUnit.MINUTES))
        .apply { if (!tlsResume) sslSocketFactory(sslContext().socketFactory, trustAll) }
        .build()

    private fun done(client: OkHttpClient) { if (client !== base) client.connectionPool.evictAll() }

    private fun error(opName: String, key: String) {
        op(opName).apply { err.increment(); errInterval.increment() }
        if (measuring) errors.computeIfAbsent("$opName $key") { LongAdder() }.increment()
    }

    private fun errorKey(code: Int, body: String): String {
        val e = runCatching { (json.parseToJsonElement(body).jsonObject["error"] as? JsonPrimitive)?.content }.getOrNull()
        return "$code:${e ?: body.take(40)}"
    }

    /**
     * A fleet that has been running holds the current full config: every device
     * starts with the version and issuedAt of the envelope the server serves
     * now, so rounds do not embed a config the device already has (the first
     * round of a device new to the server still gets one, as in the field).
     * The newest issuedAt the server ever signed, so never a `config_rollback`.
     */
    private fun preloadConfig() {
        val response = base.newCall(Request.Builder().url("$target/api/v1/certificate-config").header("X-PinVault-Features", FEATURES).build()).execute()
        val body = response.use { check(it.code == 200) { "config preload: HTTP ${it.code}" }; it.body!!.string() }
        val probe = Device("preload", devices.first().key, devices.first().spkiBase64)
        remember(probe, json.parseToJsonElement(body).jsonObject, count = false)
        // --config-issued-at: the issuedAt the fleet holds (and the server has on record as each device's watermark), see README.
        val issuedAt = o.strOrNull("config-issued-at")?.toLong() ?: probe.configIssuedAt
        devices.forEach { it.configVersion = probe.configVersion; it.configIssuedAt = issuedAt }
        println("[$label] devices hold config version ${probe.configVersion}, issuedAt $issuedAt")
    }

    fun start() {
        require(devices.isNotEmpty()) { "no devices in the keys file" }
        if (o.bool("preload-config", true)) preloadConfig()
        val ratios = mix.map { it.second }; val sum = ratios.sum()
        println("[$label] target=$target rate=$rate/s duration=${duration}s warmup=${warmup}s devices=${devices.size} " +
            "conn=$conn tlsResume=$tlsResume mix=$mix (each device every ${"%.1f".format(devices.size / (rate * (mix.firstOrNull { it.first.startsWith("attest") }?.second ?: 0.0) / sum).coerceAtLeast(1e-9))} s)")

        val reporter = Executors.newSingleThreadScheduledExecutor { r -> Thread(r, "lt-report").apply { isDaemon = true } }
        val startNanos = System.nanoTime()
        val cpu0 = processCpuNanos()
        var measureStartNanos = startNanos
        var measureCpu0 = cpu0
        reporter.scheduleAtFixedRate({
            val t = (System.nanoTime() - startNanos) / 1e9
            val line = ops.values.sortedBy { it.name }.joinToString("  ") { op ->
                val h = op.recorder.intervalHistogram
                if (measuring) op.total.add(h)
                val ok = op.okInterval.sumThenReset(); val err = op.errInterval.sumThenReset()
                "${op.name}: ok=${"%.1f".format(ok.toDouble() / reportEvery)}/s err=$err p50=${ms(h.getValueAtPercentile(50.0))} " +
                    "p95=${ms(h.getValueAtPercentile(95.0))} p99=${ms(h.getValueAtPercentile(99.0))}"
            }
            println("[$label t=${"%.0f".format(t)}s${if (measuring) "" else " warmup"}] $line inflight=${inflight.get()} lagMax=${ms(lagMaxMicros.get())}ms")
        }, reportEvery.toLong(), reportEvery.toLong(), TimeUnit.SECONDS)

        // The schedule: one slot every 1/rate s, each slot an operation drawn by the mix (deterministically spread).
        val periodNanos = (1e9 / rate).toLong()
        val totalSlots = ((warmup + duration) * rate).toLong()
        val warmupSlots = (warmup * rate).toLong()
        val credits = DoubleArray(mix.size)
        for (slot in 0 until totalSlots) {
            if (slot == warmupSlots && warmup > 0) {
                // Warm-up over: drop what was counted so far.
                ops.values.forEach { it.recorder.reset(); it.total.reset(); it.ok.reset(); it.err.reset() }
                errors.clear(); protocols.clear(); lagMaxMicros.set(0); maxInflightSeen.set(0)
                measureStartNanos = System.nanoTime(); measureCpu0 = processCpuNanos()
                measuring = true
            }
            val intended = startNanos + slot * periodNanos
            while (true) {
                val wait = intended - System.nanoTime()
                if (wait <= 0) break
                LockSupport.parkNanos(wait)
            }
            lagMaxMicros.accumulateAndGet((System.nanoTime() - intended) / 1000, ::max)
            // Weighted round robin over the mix.
            var pick = 0
            for (i in mix.indices) { credits[i] += ratios[i] / sum; if (credits[i] > credits[pick]) pick = i }
            credits[pick] -= 1.0
            val kind = mix[pick].first
            if (inflight.get() >= maxInflight) { error(kind, "gen:max_inflight"); continue }
            val device = devices[Math.floorMod(nextDevice.getAndIncrement(), devices.size)]
            when (kind) {
                "attest" -> round(device, intended, null, "attest")
                "attest-narrow" -> round(device, intended, narrowHosts, "attest-narrow")
                "config-full" -> config(device, intended, narrowed = false)
                "config-narrow" -> config(device, intended, narrowed = true)
            }
        }
        // Let the last calls finish (at most the call timeout).
        val drainUntil = System.nanoTime() + TimeUnit.SECONDS.toNanos(60)
        while (inflight.get() > 0 && System.nanoTime() < drainUntil) Thread.sleep(50)
        reporter.shutdown(); reporter.awaitTermination(5, TimeUnit.SECONDS)
        ops.values.forEach { it.total.add(it.recorder.intervalHistogram) }
        val measuredSeconds = (System.nanoTime() - measureStartNanos) / 1e9
        val genCpu = (processCpuNanos() - measureCpu0) / 1e9 / measuredSeconds
        summary(measuredSeconds, genCpu)
        // The ramp's stop rule on the step's first operation of the mix: p95 over the limit, or too many errors.
        val primary = ops[mix.first().first]
        val okCount = primary?.ok?.sum() ?: 0L
        val errCount = primary?.err?.sum() ?: 0L
        val p95 = primary?.total?.takeIf { it.totalCount > 0 }?.getValueAtPercentile(95.0)?.let { ms(it) } ?: Double.MAX_VALUE
        val errRatio = if (okCount + errCount == 0L) 1.0 else errCount.toDouble() / (okCount + errCount)
        val broken = p95 > o.double("stop-p95-ms", 1000.0) || errRatio > o.double("stop-error-ratio", 0.01)
        if (broken) println("[$label] KNEE: p95=${p95}ms errors=${"%.2f".format(errRatio * 100)}%")
        kotlin.system.exitProcess(if (broken) 3 else 0)
    }

    private fun begin() { val n = inflight.incrementAndGet(); maxInflightSeen.accumulateAndGet(n, ::max) }
    private fun end() { inflight.decrementAndGet() }

    private fun Response.protocolSeen() { if (measuring) protocols.computeIfAbsent(protocol.toString()) { LongAdder() }.increment() }

    /** One attestation round: challenge → signed report → verdict (ok = pass with a token). */
    private fun round(device: Device, intended: Long, hosts: List<String>?, name: String) {
        begin()
        val client = clientForRound()
        val challengeStart = System.nanoTime()
        client.newCall(Request.Builder().url("$target/api/v1/attest/challenge").get().build()).enqueue(object : Callback {
            override fun onFailure(call: Call, e: IOException) { error(name, "io:challenge:${e.javaClass.simpleName}"); done(client); end() }
            override fun onResponse(call: Call, response: Response) {
                val (code, body) = response.use { it.protocolSeen(); it.code to it.body!!.string() }
                if (code != 200) { error(name, "challenge " + errorKey(code, body)); done(client); end(); return }
                op("challenge").apply { record(challengeStart); ok.increment(); okInterval.increment() }
                val nonce = runCatching { json.parseToJsonElement(body).jsonObject["nonce"]!!.let { (it as JsonPrimitive).content } }.getOrNull()
                    ?: run { error(name, "challenge:bad_json"); done(client); end(); return }
                val attestStart = System.nanoTime()
                val request = Request.Builder().url("$target/api/v1/attest")
                    .post(attestBody(device, nonce, hosts).toRequestBody(JSON)).build()
                client.newCall(request).enqueue(object : Callback {
                    override fun onFailure(call: Call, e: IOException) { error(name, "io:attest:${e.javaClass.simpleName}"); done(client); end() }
                    override fun onResponse(call: Call, response: Response) {
                        try {
                            val (code2, body2) = response.use { it.code to it.body!!.string() }
                            if (code2 != 200) { error(name, errorKey(code2, body2)); return }
                            val answer = json.parseToJsonElement(body2).jsonObject
                            val result = (answer["result"] as? JsonPrimitive)?.content
                            if (result != "pass") { error(name, "200:$result:${answer["arc"]}"); return }
                            if (answer["token"] == null) { error(name, "200:pass_without_token"); return }
                            (answer["config"] as? JsonObject)?.let { remember(device, it) }
                            op("attest-call").apply { record(attestStart); ok.increment(); okInterval.increment() }
                            op(name).apply { record(intended); ok.increment(); okInterval.increment() }
                        } catch (e: Exception) {
                            error(name, "client:${e.javaClass.simpleName}")
                        } finally { done(client); end() }
                    }
                })
            }
        })
    }

    /** The config the server embedded: its version and issuedAt are what the device sends back next round. */
    private fun remember(device: Device, config: JsonObject, count: Boolean = true) {
        val payload = (config["payload"] as? JsonPrimitive)?.content ?: return
        val p = json.parseToJsonElement(payload).jsonObject
        device.configVersion = (p["version"] as? JsonPrimitive)?.intOrNull
        device.configIssuedAt = (p["issuedAt"] as? JsonPrimitive)?.longOrNull
        if (count && measuring) op("attest-config-embedded").apply { ok.increment() }
    }

    /** GET /api/v1/certificate-config as the library calls it (DefaultCertificateConfigApi): full, or narrowed by hosts + device id. */
    private fun config(device: Device, intended: Long, narrowed: Boolean) {
        begin()
        val name = if (narrowed) "config-narrow" else "config-full"
        val client = clientForRound()
        val url = if (narrowed) "$target/api/v1/certificate-config?hosts=${narrowHosts.joinToString(",")}" else "$target/api/v1/certificate-config"
        val request = Request.Builder().url(url).header("X-PinVault-Features", FEATURES)
            .apply { if (narrowed) header("X-Device-Id", device.id) }.get().build()
        client.newCall(request).enqueue(object : Callback {
            override fun onFailure(call: Call, e: IOException) { error(name, "io:${e.javaClass.simpleName}"); done(client); end() }
            override fun onResponse(call: Call, response: Response) {
                try {
                    val (code, body) = response.use { it.protocolSeen(); it.code to it.body!!.string() }
                    if (code != 200 || !body.contains("\"payload\"")) { error(name, errorKey(code, body)); return }
                    op(name).apply { record(intended); ok.increment(); okInterval.increment() }
                } finally { done(client); end() }
            }
        })
    }

    private fun summary(measuredSeconds: Double, genCpu: Double) {
        val opsJson = buildJsonObject {
            ops.values.sortedBy { it.name }.forEach { op ->
                put(op.name, buildJsonObject {
                    put("ok", op.ok.sum()); put("err", op.err.sum())
                    put("okPerSecond", op.ok.sum() / measuredSeconds)
                    if (op.total.totalCount > 0) {
                        put("p50ms", ms(op.total.getValueAtPercentile(50.0))); put("p95ms", ms(op.total.getValueAtPercentile(95.0)))
                        put("p99ms", ms(op.total.getValueAtPercentile(99.0))); put("maxms", ms(op.total.maxValue))
                    }
                })
            }
        }
        val line = buildJsonObject {
            put("label", label); put("target", target); put("offeredRate", rate); put("durationSeconds", duration); put("warmupSeconds", warmup)
            put("measuredSeconds", measuredSeconds); put("devices", devices.size); put("conn", conn); put("tlsResume", tlsResume)
            put("mix", mix.joinToString(",") { "${it.first}=${it.second}" })
            put("ops", opsJson)
            put("errors", buildJsonObject { errors.toSortedMap().forEach { (k, v) -> put(k, v.sum()) } })
            put("protocols", buildJsonObject { protocols.forEach { (k, v) -> put(k, v.sum()) } })
            put("generatorLagMaxMs", ms(lagMaxMicros.get())); put("generatorMaxInflight", maxInflightSeen.get())
            put("generatorCpuCores", genCpu)
            put("finishedAt", java.time.Instant.now().toString())
        }
        println("[$label] SUMMARY $line")
        out?.let { it.parentFile?.mkdirs(); it.appendText(line.toString() + "\n") }
    }

    private fun processCpuNanos(): Long =
        (ManagementFactory.getOperatingSystemMXBean() as? com.sun.management.OperatingSystemMXBean)?.processCpuTime ?: 0L

    companion object {
        private val JSON = "application/json".toMediaType()
        fun ms(micros: Long): Double = Math.round(micros / 10.0) / 100.0
    }
}

/**
 * `seed --db PATH --keys FILE [--devices N] [--offset K] [--config-api default-tls]`:
 * registers the devices of FILE straight into the server's database (server
 * stopped), with the server's own store and what a `warn` registration
 * without a chain records (`chain_missing`) — a population for steady-state
 * runs without spending an hour on registration rounds. Devices already on
 * record are left as they are.
 */
fun seed(o: Opts) {
    val db = com.example.pinvault.server.store.DatabaseManager(o.str("db", "pinvault.db"))
    val store = com.example.pinvault.server.store.AttestedDeviceStore(db)
    val configApi = o.str("config-api", "default-tls")
    val attestation = com.example.pinvault.server.store.KeyAttestation(false, null, "chain_missing")
    val dec = Base64.getDecoder()
    var added = 0; var kept = 0
    val started = System.nanoTime()
    File(o.str("keys", "loadtest-keys.txt")).useLines { lines ->
        lines.filter { it.isNotBlank() }.drop(o.int("offset", 0)).take(o.int("devices", Int.MAX_VALUE)).forEach { line ->
            val (id, _, spki) = line.trim().split(' ')
            if (store.get(configApi, id) != null) { kept++; return@forEach }
            store.register(configApi, id, AttestationService.sha256Hex(dec.decode(spki)), spki, attestation)
            added++
            if (added % 10_000 == 0) println("seeded $added")
        }
    }
    println("seeded $added devices ($kept already on record) in ${"%.1f".format((System.nanoTime() - started) / 1e9)} s")
}
