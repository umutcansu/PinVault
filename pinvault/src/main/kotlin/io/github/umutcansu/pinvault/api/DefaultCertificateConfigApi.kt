package io.github.umutcansu.pinvault.api

import io.github.umutcansu.pinvault.crypto.SignatureTrust
import io.github.umutcansu.pinvault.crypto.SignedConfigVerifier
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
 *
 * The updater asks a signed block for the envelope itself
 * ([SignedConfigSource]) and verifies it with the same [SignedConfigVerifier],
 * so it can keep the envelope next to the stored config; [fetchConfig] and
 * [fetchScopedConfig] verify too, for callers that only want the config.
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
    private val enrollmentUrl: String? = null,
    /**
     * Told the server's reason whenever any request here is refused with
     * `403 reenroll_required` (a revoked identity), see [ReenrollRequiredInterceptor].
     */
    private val onReenrollRequired: ((reason: String, presented: java.security.cert.X509Certificate?) -> Unit)? = null,
    /** The block's `serverScope`: the `configApiId` a signed config must name. Null = not checked. */
    serverScope: String? = null,
    /** The block's `allowUnpinnedConfigApi()`: no bootstrap pins and plain HTTP are accepted. */
    private val allowUnpinned: Boolean = false,
    /**
     * The block's `allowServerGeneratedKey()`. Without it a CSR enrollment
     * advertises only `csr`: offering `p12password` too would invite the
     * server to answer with a key of its own making, which the device then
     * refuses anyway.
     */
    private val allowServerGeneratedKey: Boolean = false
) : CertificateConfigApi, SignedConfigSource {

    /** Null = the block runs unsigned (`allowUnsigned()`). */
    private val trust: SignatureTrust? =
        signatureTrust ?: signaturePublicKey?.let { SignatureTrust.single("default", it) }

    private val verifier: SignedConfigVerifier? = trust?.let { SignedConfigVerifier(it, serverScope) }

    private val bootstrapPins: List<HostPin> = bootstrapPins

    /**
     * The pinned client every call here goes through. Its handshakes present
     * the SSL manager's current client identity; after a change (enroll,
     * renew, unenroll) [rebuildBootstrapClient] still drops the connections
     * opened with the old one.
     */
    @Volatile
    private var bootstrapClient: okhttp3.OkHttpClient = newBootstrapClient()

    private fun newBootstrapClient(): okhttp3.OkHttpClient =
        sslManager.buildBootstrapClient(bootstrapPins, onReenrollRequired?.let { ReenrollRequiredInterceptor(it) }, allowUnpinned)

    /** Swaps in a fresh pinned client, so no request rides a connection made with the previous identity. */
    internal fun rebuildBootstrapClient() {
        val old = bootstrapClient
        bootstrapClient = newBootstrapClient()
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
        val verifier = verifier
        if (verifier == null) {
            Timber.w("Config signature verification DISABLED — config integrity cannot be guaranteed. " +
                "Set signaturePublicKey in PinVaultConfig for production use.")
            return service.getConfig(configEndpoint, currentVersion)
        }

        val signed = service.getSignedConfig(configEndpoint, currentVersion)
        // The key set riding along goes first: the config in the same response
        // may already be signed by a key that set introduces.
        verifier.applyKeySet(signed)
        return verifier.verifyFetched(signed).config
    }

    /** The signed envelope as served, unverified — the caller verifies it ([SignedConfigVerifier]). */
    override suspend fun fetchSignedConfig(currentVersion: Int): SignedConfigResponse =
        service.getSignedConfig(configEndpoint, currentVersion)

    override suspend fun fetchScopedSignedConfig(
        currentVersion: Int,
        hosts: List<String>?,
        deviceId: String?
    ): SignedConfigResponse {
        val hostsParam = hosts?.takeIf { it.isNotEmpty() }?.joinToString(",")
        return if (hostsParam != null || deviceId != null) {
            service.getScopedSignedConfig(configEndpoint, currentVersion, hostsParam, deviceId)
        } else {
            service.getSignedConfig(configEndpoint, currentVersion)
        }
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
            val signatureV2 = resp.header(VAULT_SIGNATURE_V2_HEADER)
            val signaturesV2 = resp.header(VAULT_SIGNATURES_V2_HEADER)?.let(::parseSignaturesHeader)

            if (resp.code == 304) {
                return@withContext VaultFetchResponse(
                    content = ByteArray(0),
                    version = version,
                    encryption = encryption,
                    notModified = true
                )
            }

            if (!resp.isSuccessful) {
                throw VaultFetchHttpException(resp.code, resp.body?.string()?.take(200))
            }

            val bytes = resp.body?.bytes() ?: ByteArray(0)
            VaultFetchResponse(
                content = bytes,
                version = version,
                encryption = encryption,
                notModified = false,
                signature = signature,
                signatures = signatures,
                signatureV2 = signatureV2,
                signaturesV2 = signaturesV2
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

        val verifier = verifier
        if (verifier == null) {
            Timber.w("Config signature verification DISABLED (scoped fetch)")
            return if (hostsParam != null || deviceId != null) {
                service.getScopedConfig(configEndpoint, currentVersion, hostsParam, deviceId)
            } else {
                service.getConfig(configEndpoint, currentVersion)
            }
        }

        val signed = fetchScopedSignedConfig(currentVersion, hosts, deviceId)
        verifier.applyKeySet(signed)
        return verifier.verifyFetched(signed) { detail ->
            "Config signature verification failed (scoped fetch).$detail"
        }.config
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
        registerKey(deviceId, publicKeyPem, proof, purpose = null, attestationChain = emptyList())

    /** Registers the device's user-auth key (`purpose: user_auth`), which `user_auth` files are sealed for. */
    override suspend fun registerUserAuthPublicKey(deviceId: String, publicKeyPem: String, attestationChain: List<String>) =
        registerUserAuthPublicKey(deviceId, publicKeyPem, attestationChain, proof = null)

    /**
     * [registerUserAuthPublicKey] with the same proof rules as
     * [registerDevicePublicKey]. A non-empty [attestationChain] goes along as
     * `attestationChain` (older servers ignore it). The server's refusals
     * become a [UserAuthKeyRefusedException] that says what to do.
     */
    internal suspend fun registerUserAuthPublicKey(
        deviceId: String,
        publicKeyPem: String,
        attestationChain: List<String>,
        proof: DeviceKeyProof?
    ) = registerKey(deviceId, publicKeyPem, proof, purpose = USER_AUTH_KEY_PURPOSE, attestationChain = attestationChain)

    private suspend fun registerKey(
        deviceId: String,
        publicKeyPem: String,
        proof: DeviceKeyProof?,
        purpose: String?,
        attestationChain: List<String>
    ) =
        kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
            val json = org.json.JSONObject()
                .put("publicKeyPem", publicKeyPem)
                .put("algorithm", "RSA-OAEP-SHA256")
                .apply { purpose?.let { put("purpose", it) } }
                .apply { if (attestationChain.isNotEmpty()) put("attestationChain", org.json.JSONArray(attestationChain)) }
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
                if (!resp.isSuccessful && purpose == USER_AUTH_KEY_PURPOSE && (resp.code == 409 || resp.code == 403)) {
                    val answer = runCatching { org.json.JSONObject(resp.body?.string().orEmpty()) }.getOrNull()
                    UserAuthKeyRefusedException.from(resp.code, answer?.optString("error")?.ifBlank { null },
                        answer?.optString("reason")?.ifBlank { null }, attestationChain.isNotEmpty())
                        ?.let { throw it }
                }
                when {
                    resp.isSuccessful -> Timber.d("Registered device %s key (attestation chain: %d)",
                        purpose ?: "E2E", attestationChain.size)
                    resp.code == 409 -> throw Exception(
                        "Device public key registration refused (HTTP 409): another key is registered for this device; " +
                            "replacing it needs the device's token for an end_to_end or user_auth file, or an administrator reset"
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
    ): EnrollmentResult = enrollRequest(token, deviceId, deviceAlias, deviceUid, csrDer = null, requestId = null, attestationChain = emptyList(), integrityToken = null)

    /**
     * Sends the CSR along with the usual enrollment fields and the `csr`
     * feature. A server that understands it answers with a PEM chain
     * (`X-PinVault-Cert-Format: pem-chain`); an older server ignores both and
     * answers with a P12 exactly as for [enroll]. That answer is returned
     * as it came — whether a server-made key may be used is the caller's
     * decision (`allowServerGeneratedKey()`), taken where the block is known.
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
    ): EnrollmentResult = enrollRequest(token, deviceId, deviceAlias, deviceUid, csrDer, requestId, attestationChain = emptyList(), integrityToken = null)

    /**
     * [enrollWithCsr] with the key's attestation chain: a non-empty
     * [attestationChain] goes along as `"attestationChain": ["<base64 DER>", …]`,
     * leaf first (older servers ignore the field).
     */
    override suspend fun enrollWithCsr(
        token: String?,
        deviceId: String?,
        deviceAlias: String?,
        deviceUid: String?,
        csrDer: ByteArray,
        requestId: String?,
        attestationChain: List<String>
    ): EnrollmentResult = enrollRequest(token, deviceId, deviceAlias, deviceUid, csrDer, requestId, attestationChain, integrityToken = null)

    /**
     * [enrollWithCsr] with an integrity token: a non-blank [integrityToken]
     * goes along as `"integrityToken"` (older servers ignore the field).
     */
    override suspend fun enrollWithCsr(
        token: String?,
        deviceId: String?,
        deviceAlias: String?,
        deviceUid: String?,
        csrDer: ByteArray,
        requestId: String?,
        attestationChain: List<String>,
        integrityToken: String?
    ): EnrollmentResult = enrollRequest(token, deviceId, deviceAlias, deviceUid, csrDer, requestId, attestationChain, integrityToken)

    /**
     * What an enrollment request advertises. The P12 path ([enroll]) asks
     * for a one-off P12 password; a CSR enrollment asks for a chain, and adds
     * `p12password` only when the block would accept a server-made key.
     */
    internal fun enrollmentFeatures(csr: Boolean): String = when {
        !csr -> P12Rewrap.FEATURE
        allowServerGeneratedKey -> "${P12Rewrap.FEATURE},$CSR_FEATURE"
        else -> CSR_FEATURE
    }

    private suspend fun enrollRequest(
        token: String?,
        deviceId: String?,
        deviceAlias: String?,
        deviceUid: String?,
        csrDer: ByteArray?,
        requestId: String?,
        attestationChain: List<String>,
        integrityToken: String?
    ): EnrollmentResult = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
        val json = org.json.JSONObject()
        token?.let { json.put("token", it) }
        deviceId?.let { json.put("deviceId", it) }
        deviceAlias?.let { json.put("deviceAlias", it) }
        deviceUid?.let { json.put("deviceUid", it) }
        csrDer?.let { json.put("csr", android.util.Base64.encodeToString(it, android.util.Base64.NO_WRAP)) }
        requestId?.let { json.put("requestId", it) }
        if (csrDer != null && attestationChain.isNotEmpty()) json.put("attestationChain", org.json.JSONArray(attestationChain))
        // Bound to this CSR by its request hash; meaningless without one.
        if (csrDer != null && !integrityToken.isNullOrBlank()) json.put("integrityToken", integrityToken)

        val requestBody = json.toString().toRequestBody("application/json".toMediaType())
        val request = okhttp3.Request.Builder()
            .url("${enrollmentUrl ?: configUrl}$enrollmentEndpoint")
            .header("X-PinVault-Features", enrollmentFeatures(csr = csrDer != null))
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
                        // An attestation refusal says why in `reason`.
                        answer?.optString("message")?.ifBlank { null } ?: answer?.optString("reason")?.ifBlank { null }
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

/**
 * A vault download the server refused. The message keeps the earlier
 * `Vault fetch failed: HTTP <code> — <body>` form; [code] and [body] let the
 * router react to `412 user_auth_key_required`.
 */
internal class VaultFetchHttpException(val code: Int, val body: String?) :
    Exception("Vault fetch failed: HTTP $code — $body")

/**
 * The server refused the device's user-auth key. The message says what the
 * app (or its operator) has to do; [serverError] is the server's `error`.
 */
internal class UserAuthKeyRefusedException(val httpStatus: Int, val serverError: String, message: String) : Exception(message) {
    companion object {
        /** The refusal for a known `error`, or null to fall back to the generic message. */
        fun from(httpStatus: Int, error: String?, reason: String?, sentChain: Boolean): UserAuthKeyRefusedException? =
            when (error) {
                "user_auth_key_exists" -> UserAuthKeyRefusedException(
                    httpStatus, error,
                    "The server keeps another user-auth key for this device (HTTP $httpStatus user_auth_key_exists) and " +
                        "replaces it only with a valid key attestation" +
                        (if (sentChain) "" else ", which this device could not provide") +
                        ". An administrator must reset this device's user-auth key on the server; then fetch again."
                )
                "attestation_required" -> UserAuthKeyRefusedException(
                    httpStatus, error,
                    "The server accepts user-auth keys only with an Android key attestation (HTTP $httpStatus " +
                        "attestation_required) and this device sent none: its Keystore could not attest the key."
                )
                "attestation_invalid" -> UserAuthKeyRefusedException(
                    httpStatus, error,
                    "The server refused this device's key attestation (HTTP $httpStatus attestation_invalid)" +
                        (reason?.let { ": $it" } ?: "") + "."
                )
                else -> null
            }
    }
}

/** `purpose` of a user-auth key registration. */
internal const val USER_AUTH_KEY_PURPOSE = "user_auth"

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

/**
 * Vault signature headers of the v2 scheme, sent next to the v1 headers
 * (`X-Vault-Signature`, `X-Vault-Signatures`) in the same encoding: the
 * primary signer's Base64 signature, and comma-separated `keyId:signature`
 * pairs. v2 signs `pinvault-vault-file:v2:<configApiId>:<key>:<version>:<sha256 hex>`.
 */
internal const val VAULT_SIGNATURE_V2_HEADER = "X-Vault-Signature-V2"
internal const val VAULT_SIGNATURES_V2_HEADER = "X-Vault-Signatures-V2"
