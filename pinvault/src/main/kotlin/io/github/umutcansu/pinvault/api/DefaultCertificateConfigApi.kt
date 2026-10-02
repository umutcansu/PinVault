package io.github.umutcansu.pinvault.api

import io.github.umutcansu.pinvault.crypto.SignatureTrust
import io.github.umutcansu.pinvault.internal.P12Rewrap
import io.github.umutcansu.pinvault.model.CertificateConfig
import io.github.umutcansu.pinvault.model.ClientCertRenewalResponse
import io.github.umutcansu.pinvault.model.EnrollmentResult
import io.github.umutcansu.pinvault.model.HostPin
import io.github.umutcansu.pinvault.model.SignatureEntry
import io.github.umutcansu.pinvault.model.SignedConfigResponse
import io.github.umutcansu.pinvault.model.VaultDownloadReport
import io.github.umutcansu.pinvault.model.VaultFetchResponse
import io.github.umutcansu.pinvault.ssl.DynamicSSLManager
import com.google.gson.Gson
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.ResponseBody
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory
import retrofit2.http.GET
import retrofit2.http.Header
import retrofit2.http.POST
import retrofit2.http.Body
import retrofit2.http.Query
import retrofit2.http.QueryMap
import retrofit2.http.Url
import timber.log.Timber

/**
 * Default implementation of [CertificateConfigApi] using Retrofit/OkHttp.
 *
 * All endpoint paths are configurable. With a signing key configured, config
 * responses must be signed envelopes that pass [SignatureTrust] (one or more
 * trusted ECDSA-SHA256 signatures, optionally carrying a signing-key set).
 */
internal class DefaultCertificateConfigApi(
    private val configUrl: String,
    private val configEndpoint: String = "api/v1/certificate-config",
    private val healthEndpoint: String = "health",
    private val clientCertEndpoint: String = "api/v1/client-certs",
    private val enrollmentEndpoint: String = "api/v1/client-certs/enroll",
    private val vaultReportEndpoint: String = "api/v1/vault/report",
    /** Single-key shorthand, used when [signatureTrust] is not given. */
    signaturePublicKey: String? = null,
    bootstrapPins: List<HostPin>,
    private val sslManager: DynamicSSLManager,
    signatureTrust: SignatureTrust? = null,
    /** The block's P12 password; host client certificates are re-wrapped to it. */
    private val clientKeyPassword: String? = null,
    /** Base URL for first enrollment (a TLS listener); null = [configUrl]. */
    private val enrollmentUrl: String? = null
) : CertificateConfigApi {

    /** Null = the block runs unsigned (`allowUnsigned()`). */
    private val trust: SignatureTrust? =
        signatureTrust ?: signaturePublicKey?.let { SignatureTrust.single("default", it) }

    private val gson = Gson()

    private val bootstrapPins: List<HostPin> = bootstrapPins

    /**
     * The pinned client every call here goes through. It captures the SSL
     * manager's key managers when built, so a client-certificate change
     * (enroll, renew, unenroll) must go through [rebuildBootstrapClient] —
     * otherwise the Config API keeps seeing the old identity until restart.
     */
    @Volatile
    private var bootstrapClient: okhttp3.OkHttpClient = sslManager.buildBootstrapClient(bootstrapPins)

    /** Rebuilds the pinned client so it presents the SSL manager's current client identity. */
    internal fun rebuildBootstrapClient() {
        val old = bootstrapClient
        bootstrapClient = sslManager.buildBootstrapClient(bootstrapPins)
        Thread({ old.connectionPool.evictAll() }, "PinVault-EvictBootstrap").apply { isDaemon = true }.start()
        Timber.d("Bootstrap client rebuilt")
    }

    private val service: DynamicConfigService by lazy {
        Retrofit.Builder()
            .baseUrl(configUrl)
            // Resolved per call, so a rebuilt bootstrap client is picked up.
            .callFactory(okhttp3.Call.Factory { request -> bootstrapClient.newCall(request) })
            .addConverterFactory(GsonConverterFactory.create())
            .build()
            .create(DynamicConfigService::class.java)
    }

    override suspend fun healthCheck(): Boolean {
        return try {
            val response = service.healthCheck(healthEndpoint)
            val isHealthy = response["status"] == "ok"
            Timber.d("Health check: %s", if (isHealthy) "ok" else "unhealthy")
            isHealthy
        } catch (e: Exception) {
            Timber.e(e, "Health check failed")
            false
        }
    }

    override suspend fun fetchConfig(currentVersion: Int): CertificateConfig {
        val trust = trust
        if (trust == null) {
            Timber.w("Config signature verification DISABLED — config integrity cannot be guaranteed. " +
                "Set signaturePublicKey in PinVaultConfig for production use.")
            return service.getConfig(configEndpoint, currentVersion)
        }

        val signed = service.getSignedConfig(configEndpoint, currentVersion)
        return verifiedConfig(signed, trust) { detail ->
            "Config signature verification failed — possible tampering detected. " +
                "Keeping previous safe config.$detail"
        }
    }

    /**
     * Checks a signed envelope and returns the config inside it.
     *
     * A signing-key set riding along is applied FIRST: the config in the same
     * response may already be signed by a key that set introduces. A set that
     * fails its own checks throws and fails the whole response; a valid one
     * stays applied even if the config then fails, so a revocation sticks.
     */
    private fun verifiedConfig(
        signed: SignedConfigResponse,
        trust: SignatureTrust,
        failureMessage: (detail: String) -> String
    ): CertificateConfig {
        trust.applyKeySetUpdate(signed.signingKeys)

        // `signatures` (several signers) wins over the single legacy field.
        // Gson leaves absent fields null whatever their Kotlin type says.
        @Suppress("USELESS_CAST")
        val single = (signed.signature as String?)?.let { SignatureEntry(signed.keyId, it) }
        val entries = signed.signatures?.takeIf { it.isNotEmpty() } ?: listOfNotNull(single)

        @Suppress("USELESS_CAST")
        val payload = (signed.payload as String?) ?: throw SecurityException(failureMessage(" The envelope has no payload."))
        val verification = trust.verifyConfig(payload, entries)
        if (!verification.ok) {
            throw SecurityException(failureMessage(verification.detail))
        }
        Timber.d("Config signature verified ✓ — signed by %s", verification.signedBy)

        val config = gson.fromJson(payload, CertificateConfig::class.java)
        enforceFreshness(config)
        return config
    }

    /**
     * The host's client certificate, wrapped with this block's
     * [clientKeyPassword]: a server that sends a one-off password
     * (`X-P12-Password`) gets its bundle re-wrapped here, so the app never
     * needs a password chosen on the server.
     */
    override suspend fun downloadHostClientCert(hostname: String): ByteArray {
        val url = "$clientCertEndpoint/$hostname/download"
        Timber.d("Downloading host client cert: %s", url)
        val response = service.downloadP12(url)
        if (!response.isSuccessful) throw retrofit2.HttpException(response)
        val bytes = response.body()?.bytes() ?: throw Exception("Empty host client certificate response")
        val oneOff = response.headers()[P12Rewrap.PASSWORD_HEADER]
        return if (oneOff != null && clientKeyPassword != null) P12Rewrap.rewrap(bytes, oneOff, clientKeyPassword) else bytes
    }

    override suspend fun downloadVaultFile(endpoint: String): ByteArray {
        Timber.d("Downloading vault file: %s", endpoint)
        val body = service.downloadBinary(endpoint)
        return body.bytes()
    }

    /**
     * V2 download with full HTTP metadata. Handles:
     *   - ?version=N query for 304 support
     *   - X-Device-Id header (required when access_policy is token/token_mtls)
     *   - X-Vault-Token header (when accessToken is provided)
     *   - X-Vault-Version / X-Vault-Encryption response headers
     *   - 304 Not Modified → notModified=true, empty content
     *   - 401/other failures → throws Exception
     *
     * OkHttp's synchronous `.execute()` is a blocking call; this method must
     * run off the main thread. We wrap in [Dispatchers.IO] so callers who
     * forget to dispatch don't hit [NetworkOnMainThreadException].
     */
    override suspend fun downloadVaultFileWithMeta(
        endpoint: String,
        currentVersion: Int,
        deviceId: String?,
        accessToken: String?
    ): VaultFetchResponse = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
        Timber.d("Downloading vault file (meta): %s v=%d", endpoint, currentVersion)
        val url = if (endpoint.contains("?")) "$endpoint&version=$currentVersion"
                  else "$endpoint?version=$currentVersion"

        val requestBuilder = okhttp3.Request.Builder().url("${configUrl}$url").get()
        deviceId?.let { requestBuilder.header("X-Device-Id", it) }
        accessToken?.let { requestBuilder.header("X-Vault-Token", it) }

        val response = bootstrapClient.newCall(requestBuilder.build()).execute()
        response.use { resp ->
            val version = resp.header("X-Vault-Version")?.toIntOrNull() ?: currentVersion
            val encryption = resp.header("X-Vault-Encryption") ?: "plain"
            val signature = resp.header("X-Vault-Signature")
            val signatures = resp.header("X-Vault-Signatures")?.let(::parseSignaturesHeader)

            if (resp.code == 304) {
                return@withContext VaultFetchResponse(
                    content = ByteArray(0),
                    version = version,
                    encryption = encryption,
                    notModified = true
                )
            }

            if (!resp.isSuccessful) {
                throw Exception("Vault fetch failed: HTTP ${resp.code} — ${resp.body?.string()?.take(200)}")
            }

            val bytes = resp.body?.bytes() ?: ByteArray(0)
            VaultFetchResponse(
                content = bytes,
                version = version,
                encryption = encryption,
                notModified = false,
                signature = signature,
                signatures = signatures
            )
        }
    }

    /**
     * `X-Vault-Signatures: <keyId>:<signature>, <keyId>:<signature>` — one
     * entry per signing key. Base64 never contains `:` or `,`, so the split is
     * unambiguous; an entry without a key id is just the signature.
     */
    private fun parseSignaturesHeader(value: String): List<SignatureEntry> =
        value.split(',').map { it.trim() }.filter { it.isNotEmpty() }.map { entry ->
            val parts = entry.split(':', limit = 2)
            if (parts.size == 2) SignatureEntry(keyId = parts[0], signature = parts[1])
            else SignatureEntry(signature = entry)
        }

    /**
     * Scoped config fetch. Sends `?hosts=a,b,c` query param and/or X-Device-Id
     * header so the server can filter pins per the device's ACL.
     */
    override suspend fun fetchScopedConfig(
        currentVersion: Int,
        hosts: List<String>?,
        deviceId: String?
    ): CertificateConfig {
        val hostsParam = hosts?.takeIf { it.isNotEmpty() }?.joinToString(",")

        val trust = trust
        if (trust == null) {
            Timber.w("Config signature verification DISABLED (scoped fetch)")
            return if (hostsParam != null || deviceId != null) {
                service.getScopedConfig(configEndpoint, currentVersion, hostsParam, deviceId)
            } else {
                service.getConfig(configEndpoint, currentVersion)
            }
        }

        val signed = if (hostsParam != null || deviceId != null) {
            service.getScopedSignedConfig(configEndpoint, currentVersion, hostsParam, deviceId)
        } else {
            service.getSignedConfig(configEndpoint, currentVersion)
        }

        return verifiedConfig(signed, trust) { detail ->
            "Config signature verification failed (scoped fetch).$detail"
        }
    }

    /**
     * Rejects signed configs that fall outside the server-controlled freshness
     * window. Guards against replay of older signed payloads even when the
     * signature is still cryptographically valid: a captured config becomes
     * unusable once the wall clock crosses [CertificateConfig.expiresAt].
     *
     * Missing [CertificateConfig.expiresAt] (= 0L) is treated as an error
     * rather than silently accepted — a server that returns signed configs
     * MUST populate the freshness fields, otherwise an attacker can strip
     * them and bypass this defense.
     *
     * Replay against the same `issuedAt` is caught by the updater layer
     * (which compares against the previously persisted `issuedAt`) — this
     * method only enforces the absolute expiry window.
     */
    private fun enforceFreshness(config: CertificateConfig) {
        val now = System.currentTimeMillis()
        if (config.expiresAt <= 0L) {
            throw SecurityException(
                "Signed config missing expiresAt — refusing to apply. " +
                "Server must populate expiresAt (Unix epoch ms) to enable replay protection."
            )
        }
        if (config.expiresAt <= now) {
            throw SecurityException(
                "Signed config expired: expiresAt=${config.expiresAt}, now=$now " +
                "(stale by ${now - config.expiresAt}ms). Possible replay attack."
            )
        }
    }

    /** Register RSA public key for E2E vault file encryption. */
    override suspend fun registerDevicePublicKey(deviceId: String, publicKeyPem: String) =
        registerDevicePublicKey(deviceId, publicKeyPem, proof = null)

    /**
     * Registers the device's RSA public key, with [proof] when the router has
     * one: over a TLS listener the server keeps the first key it was given
     * and replaces it only for a request that carries the device's token for
     * an end_to_end file (`X-Vault-Key` + `X-Vault-Token`). Over mTLS the
     * client certificate is the proof and the headers are ignored.
     */
    internal suspend fun registerDevicePublicKey(deviceId: String, publicKeyPem: String, proof: DeviceKeyProof?) =
        kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
            val json = org.json.JSONObject()
                .put("publicKeyPem", publicKeyPem)
                .put("algorithm", "RSA-OAEP-SHA256")
                .toString()
            val requestBody = json.toRequestBody("application/json".toMediaType())
            val request = okhttp3.Request.Builder()
                .url("${configUrl}api/v1/vault/devices/$deviceId/public-key")
                .apply {
                    proof?.let {
                        header("X-Vault-Key", it.vaultKey)
                        header("X-Vault-Token", it.token)
                    }
                }
                .post(requestBody)
                .build()
            bootstrapClient.newCall(request).execute().use { resp ->
                when {
                    resp.isSuccessful -> Timber.d("Registered device public key: %s", deviceId)
                    resp.code == 409 -> throw Exception(
                        "Device public key registration refused (HTTP 409): another key is registered for this device; " +
                            "replacing it needs the device's token for an end_to_end file, or an administrator reset"
                    )
                    resp.code == 403 -> throw Exception(
                        "Device public key registration refused (HTTP 403): the client certificate does not belong to this device"
                    )
                    else -> throw Exception("Device public key registration failed: HTTP ${resp.code}")
                }
            }
        }

    override suspend fun enroll(
        token: String?,
        deviceId: String?,
        deviceAlias: String?,
        deviceUid: String?
    ): EnrollmentResult = enrollRequest(token, deviceId, deviceAlias, deviceUid, csrDer = null, requestId = null)

    /**
     * Sends the CSR along with the usual enrollment fields and the `csr`
     * feature. A server that understands it answers with a PEM chain
     * (`X-PinVault-Cert-Format: pem-chain`); an older server ignores both and
     * answers with a P12 exactly as for [enroll] — one request either way, so
     * a one-time token is never spent twice.
     *
     * With [requestId] the device asks again whether the enrollment it was
     * told to wait for (HTTP 202) has been approved.
     */
    override suspend fun enrollWithCsr(
        token: String?,
        deviceId: String?,
        deviceAlias: String?,
        deviceUid: String?,
        csrDer: ByteArray,
        requestId: String?
    ): EnrollmentResult = enrollRequest(token, deviceId, deviceAlias, deviceUid, csrDer, requestId)

    private suspend fun enrollRequest(
        token: String?,
        deviceId: String?,
        deviceAlias: String?,
        deviceUid: String?,
        csrDer: ByteArray?,
        requestId: String?
    ): EnrollmentResult = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
        val json = org.json.JSONObject()
        token?.let { json.put("token", it) }
        deviceId?.let { json.put("deviceId", it) }
        deviceAlias?.let { json.put("deviceAlias", it) }
        deviceUid?.let { json.put("deviceUid", it) }
        csrDer?.let { json.put("csr", android.util.Base64.encodeToString(it, android.util.Base64.NO_WRAP)) }
        requestId?.let { json.put("requestId", it) }

        val requestBody = json.toString().toRequestBody("application/json".toMediaType())
        val request = okhttp3.Request.Builder()
            .url("${enrollmentUrl ?: configUrl}$enrollmentEndpoint")
            .header("X-PinVault-Features", if (csrDer != null) "${P12Rewrap.FEATURE},$CSR_FEATURE" else P12Rewrap.FEATURE)
            .post(requestBody)
            .build()

        bootstrapClient.newCall(request).execute().use { response ->
            // Taken, but an administrator approves the device first (an enrollment
            // code whose policy asks for it): no certificate yet, a request id.
            if (response.code == 202) {
                val answer = runCatching { org.json.JSONObject(response.body?.string().orEmpty()) }.getOrNull()
                val id = answer?.optString("requestId")?.ifBlank { null }
                    ?: throw Exception("Enrollment answered 202 without a requestId")
                throw io.github.umutcansu.pinvault.model.EnrollmentPendingException(
                    id,
                    answer?.optString("clientId")?.ifBlank { null },
                    answer?.optString("message")?.ifBlank { null },
                    response.header("Retry-After")?.trim()?.toIntOrNull()
                )
            }
            if (!response.isSuccessful) {
                // A refusal carries its reason in the body (`device_already_enrolled`,
                // `revoked`, …); keep it, the app shows it to the user.
                if (response.code in 400..499) {
                    val answer = runCatching { org.json.JSONObject(response.body?.string().orEmpty()) }.getOrNull()
                    throw io.github.umutcansu.pinvault.model.EnrollmentRefusedException(
                        response.code,
                        answer?.optString("error")?.ifBlank { null },
                        answer?.optString("message")?.ifBlank { null }
                    )
                }
                throw Exception("Enrollment failed — HTTP ${response.code}")
            }
            val body = response.body?.bytes() ?: throw Exception("Empty enrollment response")

            if (response.header(CERT_FORMAT_HEADER) == CERT_FORMAT_PEM_CHAIN) {
                val chain = parseChainResponse(String(body, Charsets.UTF_8))
                Timber.d("Enrollment successful — certificate chain of %d", chain.size)
                EnrollmentResult(ByteArray(0), null, null, chain)
            } else {
                Timber.d("Enrollment successful — %d bytes", body.size)
                EnrollmentResult(body, response.header("X-P12-SHA256"), response.header(P12Rewrap.PASSWORD_HEADER))
            }
        }
    }

    /**
     * `POST <base><clientCertEndpoint>/renew` with the CSR. Over the block's
     * own client the presented certificate identifies the device; over
     * [recoveryUrl] (no client certificate) the body's `clientId` does, and
     * the server checks the CSR signature against the key it registered.
     */
    override suspend fun renewClientCert(
        clientId: String,
        csrDer: ByteArray,
        recoveryUrl: String?
    ): ClientCertRenewalResponse = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
        val json = org.json.JSONObject()
            .put("clientId", clientId)
            .put("csr", android.util.Base64.encodeToString(csrDer, android.util.Base64.NO_WRAP))
        val request = okhttp3.Request.Builder()
            .url("${recoveryUrl ?: configUrl}$clientCertEndpoint/renew")
            .header("X-PinVault-Features", CSR_FEATURE)
            .post(json.toString().toRequestBody("application/json".toMediaType()))
            .build()

        bootstrapClient.newCall(request).execute().use { response ->
            val body = response.body?.string().orEmpty()
            when (response.code) {
                200 -> ClientCertRenewalResponse.Issued(parseChainResponse(body))
                403 -> {
                    val error = runCatching { org.json.JSONObject(body).optString("error") }.getOrNull()
                    if (error == REENROLL_REQUIRED) {
                        val reason = runCatching { org.json.JSONObject(body).optString("message") }.getOrNull()
                        ClientCertRenewalResponse.ReenrollRequired(reason?.ifBlank { null } ?: REENROLL_REQUIRED)
                    } else {
                        throw Exception("Certificate renewal refused — HTTP 403 ${error.orEmpty()}")
                    }
                }
                404, 405 -> ClientCertRenewalResponse.Unsupported
                else -> throw Exception("Certificate renewal failed — HTTP ${response.code}")
            }
        }
    }

    private fun parseChainResponse(body: String): List<String> {
        val array = org.json.JSONObject(body).optJSONArray("chain")
            ?: throw Exception("Certificate response has no chain")
        val chain = (0 until array.length()).map { array.getString(it) }
        if (chain.isEmpty()) throw Exception("Certificate response has an empty chain")
        return chain
    }

    override suspend fun reportVaultDownload(report: VaultDownloadReport) =
        kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
            try {
                val json = org.json.JSONObject()
                    .put("key", report.key)
                    .put("version", report.version)
                    .put("status", report.status)
                    .put("deviceManufacturer", report.deviceManufacturer)
                    .put("deviceModel", report.deviceModel)
                    .put("enrollmentLabel", report.enrollmentLabel)
                    .put("deviceId", report.deviceId)
                    .put("deviceAlias", report.deviceAlias)
                    .apply { report.failureReason?.let { put("failureReason", it) } }
                    .apply { report.authMethod?.let { put("authMethod", it) } }
                    .toString()

                val requestBody = json.toRequestBody("application/json".toMediaType())
                val request = okhttp3.Request.Builder()
                    .url("${configUrl}$vaultReportEndpoint")
                    .post(requestBody)
                    .build()

                val reportClient = bootstrapClient.newBuilder()
                    .connectTimeout(5, java.util.concurrent.TimeUnit.SECONDS)
                    .readTimeout(5, java.util.concurrent.TimeUnit.SECONDS)
                    .build()

                reportClient.newCall(request).execute().close()
                Timber.d("Vault report sent: %s → %s", report.key, report.status)
            } catch (e: Exception) {
                Timber.e(e, "Failed to report vault download: %s", report.key)
            }
        }
}

/**
 * Proof that lets a device replace its registered E2E key over a TLS
 * listener: its access token for an end_to_end vault file ([vaultKey] is the
 * server-side key, the last segment of the file's endpoint).
 */
internal data class DeviceKeyProof(val vaultKey: String, val token: String) {
    /** Never prints the token. */
    override fun toString() = "DeviceKeyProof(vaultKey=$vaultKey, token=***)"
}

/** Uses @Url so endpoint paths are determined at runtime, not compile time. */
internal interface DynamicConfigService {
    @GET
    suspend fun healthCheck(@retrofit2.http.Url url: String): Map<String, String>

    @GET
    suspend fun getConfig(
        @retrofit2.http.Url url: String,
        @Query("currentVersion") currentVersion: Int
    ): CertificateConfig

    @GET
    @retrofit2.http.Headers(FEATURES_HEADER)
    suspend fun getSignedConfig(
        @retrofit2.http.Url url: String,
        @Query("currentVersion") currentVersion: Int
    ): SignedConfigResponse

    /** V2 scoped config fetch. `hosts` is null when not filtering. */
    @GET
    suspend fun getScopedConfig(
        @retrofit2.http.Url url: String,
        @Query("currentVersion") currentVersion: Int,
        @Query("hosts") hosts: String?,
        @Header("X-Device-Id") deviceId: String?
    ): CertificateConfig

    @GET
    @retrofit2.http.Headers(FEATURES_HEADER)
    suspend fun getScopedSignedConfig(
        @retrofit2.http.Url url: String,
        @Query("currentVersion") currentVersion: Int,
        @Query("hosts") hosts: String?,
        @Header("X-Device-Id") deviceId: String?
    ): SignedConfigResponse

    @GET
    suspend fun downloadBinary(@Url url: String): ResponseBody

    /** A P12 download that asks for a per-response password and keeps the response headers. */
    @GET
    @retrofit2.http.Headers(P12_FEATURES_HEADER)
    suspend fun downloadP12(@Url url: String): retrofit2.Response<ResponseBody>
}

/**
 * Sent with every signed-config request so a backend knows what this client
 * understands: `redelivery` — the same signed config may be served again
 * (signature caching); `multisig` — the `signatures` field; `keyset` —
 * signing-key sets. A backend must not rely on any of these without it.
 */
internal const val FEATURES_HEADER = "X-PinVault-Features: redelivery,multisig,keyset"

/**
 * Sent with P12 requests (enrollment, host client certificates): `p12password`
 * — wrap the bundle with a one-off password and send it in `X-P12-Password`,
 * instead of a password the app would have to carry.
 */
internal const val P12_FEATURES_HEADER = "X-PinVault-Features: p12password"

/**
 * Feature sent with enrollment and renewal: `csr` — the body carries a
 * PKCS#10 request over the device's own key, answer with a PEM chain
 * ([CERT_FORMAT_HEADER]) instead of a P12.
 */
internal const val CSR_FEATURE = "csr"

/** Response header that marks a certificate-chain answer to a CSR request. */
internal const val CERT_FORMAT_HEADER = "X-PinVault-Cert-Format"
internal const val CERT_FORMAT_PEM_CHAIN = "pem-chain"

/** The `error` value a server sends when an identity must enroll again. */
internal const val REENROLL_REQUIRED = "reenroll_required"
