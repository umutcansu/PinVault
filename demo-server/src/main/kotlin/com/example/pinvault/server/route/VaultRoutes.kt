package com.example.pinvault.server.route

import com.example.pinvault.server.plugin.ApiKeyPolicy
import com.example.pinvault.server.plugin.RESERVED_VAULT_SEGMENTS
import com.example.pinvault.server.plugin.receiveLimitedBytes
import com.example.pinvault.server.plugin.receiveLimitedJson
import com.example.pinvault.server.service.ConfigSigningService
import com.example.pinvault.server.service.VaultAccessTokenService
import com.example.pinvault.server.service.VaultEncryptionService
import com.example.pinvault.server.store.DevicePublicKeyStore
import com.example.pinvault.server.store.VaultDistributionStore
import com.example.pinvault.server.store.VaultFileStore
import com.example.pinvault.server.store.VaultFileTokenStore
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.plugins.origin
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.serialization.json.*
import org.slf4j.LoggerFactory
import java.time.Instant

private val log = LoggerFactory.getLogger("VaultRoutes")

/**
 * Vault file routes. Every route is scoped to [configApiId] — the same key can
 * exist under different Config APIs independently. All client-facing routes
 * enforce the file's [access_policy] before returning content.
 *
 * Registered once per Config API module in Main.kt, so each listener carries
 * its own scope. These are the DEVICE endpoints only: download, download
 * report and device-key registration. Vault administration (upload, delete,
 * policy, tokens, distributions, key resets) is not served on the
 * device-facing ports at all: it lives on the management listener under
 * `/api/v1/config-apis/{configApiId}/vault/...` ([scopedVaultAdminRoutes]),
 * where it can wait for a second admin (two-person approval). The management
 * server does not mount the routes of this file.
 *
 * Because [configApiId] is a parameter (not a URL component) here, the same
 * route path `/api/v1/vault/{key}` resolves to different scopes on different
 * ports.
 */
fun Route.vaultRoutes(
    configApiId: String,
    vaultFileStore: VaultFileStore,
    distStore: VaultDistributionStore,
    tokenStore: VaultFileTokenStore,
    publicKeyStore: DevicePublicKeyStore,
    tokenService: VaultAccessTokenService,
    encryptionService: VaultEncryptionService,
    signingService: ConfigSigningService? = null,
    /**
     * Needed only by the `token_mtls` policy: lets a certificate issued under a
     * token enrollment (where the client id is admin-chosen, not the device's
     * ANDROID_ID) be matched to the `X-Device-Id` recorded at enrollment time.
     * Null falls back to the direct clientId == deviceId rule.
     */
    clientCertStore: com.example.pinvault.server.store.ClientCertStore? = null,
    adminApiKeyRequired: Boolean = true,
    /**
     * Source of the admin key for `api_key`-policy downloads. Defaults to the
     * `API_KEY` env var (same as the ApiKeyAuth plugin); tests inject a value.
     */
    apiKeyProvider: () -> String? = { ApiKeyPolicy.configuredKey() },
    /**
     * The scope's `config_apis.vault_enabled` switch, read per request so a
     * dashboard toggle takes effect without restarting the listener. Default
     * `{ true }` keeps listeners that have no registry row (tests, embedded
     * use) behaving exactly as before.
     *
     * Only the client-facing download is gated — see the route below.
     */
    vaultEnabledProvider: () -> Boolean = { true },
    /**
     * Downloads served at once per source address (`VAULT_DOWNLOAD_CONCURRENCY`,
     * default 4); null = unlimited. A fifth gets 429 with `Retry-After: 1`.
     */
    downloadSlots: com.example.pinvault.server.service.ConcurrencyLimiter? = com.example.pinvault.server.service.ConcurrencyLimiter(4),
    /**
     * Downloads served at once in total, whatever the source
     * (`VAULT_DOWNLOAD_CONCURRENCY_TOTAL`, default 16); null = unlimited. Every
     * download holds the whole file in memory, so the per-address cap alone
     * lets a few addresses fill the heap. Beyond it: 429 with `Retry-After: 1`.
     */
    downloadSlotsTotal: com.example.pinvault.server.service.ConcurrencyLimiter? = null,
    /**
     * Produces (and, with `CONFIG_SIGNATURE_CACHE`, caches) the vault file
     * signatures. Null = sign per request with [signingService].
     */
    signedConfigService: com.example.pinvault.server.service.SignedConfigService? = null,
    /** Where E2E key registrations, replacements and resets are recorded; null = nowhere. */
    audit: com.example.pinvault.server.service.AuditLog? = null,
    /** Records refused E2E key registrations without flooding the audit log; null = not recorded. */
    keyRefusals: com.example.pinvault.server.service.AuthFailureRecorder? = null,
    /**
     * Counts the E2E keys a source address writes without a client
     * certificate (`DEVICE_KEY_RATE_LIMIT`); null = unlimited. With a
     * certificate a device can only write its own slot, so it is not counted.
     */
    keyLimiter: com.example.pinvault.server.service.RateLimiter? = null,
    /** Key replacements per identity over a certificate (`KEY_REPLACEMENT_RATE_LIMIT`); null = unlimited. */
    keyReplacementLimiter: com.example.pinvault.server.service.RateLimiter? = null,
    /** Most device keys this scope stores (`DEVICE_KEY_LIMIT`); a new device beyond it gets 503. */
    maxDeviceKeys: Int = Int.MAX_VALUE,
    /**
     * Whether a device id belongs to a revoked identity (and to no active one).
     * An AUTHENTICATED request for such a device (a valid vault token, a
     * client certificate bound to it — never an attestation alone) gets `403
     * reenroll_required`; anyone else is handled exactly as for any other
     * device id, so no answer tells strangers which device ids were revoked.
     * Default: never.
     */
    deviceRevoked: (deviceId: String) -> Boolean = { false },
    /**
     * Checks a user-auth key's Android Key Attestation chain. Null = the
     * Google hardware attestation roots, no package or signer check.
     */
    userAuthAttestation: com.example.pinvault.server.service.AndroidKeyAttestation? = null,
    /** `USER_AUTH_ATTESTATION`: off | warn (default) | enforce. */
    userAuthAttestationMode: com.example.pinvault.server.service.UserAuthAttestationMode =
        com.example.pinvault.server.service.UserAuthAttestationMode.WARN,
    /**
     * Apple App Attest in place of the Android chain for an iPhone's user-auth
     * key (`appAttestation`, PORTING.md §6); null = `APP_ATTEST_APP_IDS` empty,
     * the field is not read.
     */
    appAttest: com.example.pinvault.server.service.attestation.AppAttestVerifier? = null,
    /**
     * Records that the client certificate of `clientId` proved it acts for
     * `deviceId` (a vault token of the device used over it, or a device key
     * registered over it together with the device's token or re-registering
     * the key the device had on file before the identity enrolled). Revocation
     * cuts such devices off; the device id an identity merely claimed at
     * enrollment, or a key it registered itself, is not enough. Default: nowhere.
     */
    deviceProven: (clientId: String, deviceId: String, proof: String) -> Unit = { _, _, _ -> },
    /** How many download reports an address or a device may file; null = unlimited. */
    reportLimits: ReportLimits? = null,
    /** Unused since uploads left the device listeners ([scopedVaultAdminRoutes] has the cap); kept for callers that pass it. */
    @Suppress("UNUSED_PARAMETER") maxFileBytes: Long = DEFAULT_VAULT_MAX_FILE_BYTES
) {
    // Each device's USER-AUTH key (`device_user_auth_keys`), for `user_auth` files.
    val userAuthKeyStore = publicKeyStore.userAuthKeys()
    val attestation by lazy {
        userAuthAttestation ?: com.example.pinvault.server.service.AndroidKeyAttestation(
            com.example.pinvault.server.service.AndroidKeyAttestation.googleRoots()
        )
    }
    val vaultSigner = signedConfigService ?: signingService?.let { com.example.pinvault.server.service.SignedConfigService(it) }

    /**
     * Why a stored user-auth key may not be sealed for now, or null: see the
     * download route. `key_not_attested` (enforce), `time_bound_key` /
     * `key_kind_unknown` (USER_AUTH_REQUIRE_PER_USE). Reads the verifier's
     * settings only when one was given (the Google-roots default has none).
     * An iPhone's key admitted by App Attest (kind `app_attest`) counts as
     * attested; its access control cannot be read on the server, so
     * USER_AUTH_REQUIRE_PER_USE takes the genuine library's per-use key on
     * Apple's word that the genuine app sent it (ATTESTATION.md §12).
     */
    fun userAuthKeyUnusable(record: com.example.pinvault.server.store.KeyAttestation?): String? {
        if (userAuthAttestationMode == com.example.pinvault.server.service.UserAuthAttestationMode.OFF) return null
        val requirePerUse = userAuthAttestation?.requirePerUse == true
        return when {
            userAuthAttestationMode == com.example.pinvault.server.service.UserAuthAttestationMode.ENFORCE && record?.attested != true -> KEY_NOT_ATTESTED
            requirePerUse && record?.attested == true && record.keyKind == null -> KEY_KIND_UNKNOWN
            requirePerUse && record?.keyKind == com.example.pinvault.server.service.AndroidKeyAttestation.KeyKind.TIME_BOUND -> TIME_BOUND_KEY
            else -> null
        }
    }

    route("/api/v1/vault") {

        // ── Client-facing: download + report ────────────────────────

        /**
         * Download a vault file. Supports version-based 304.
         *
         * The scope's `vault_enabled` switch is checked FIRST, before the key
         * even resolves: when an operator turns the vault off on a Config API,
         * distribution from that scope must stop immediately. It answers 403
         * for every key, present or not, so a disabled vault does not leak
         * which keys exist.
         *
         * The switch is intentionally *not* applied to the admin routes of the
         * management listener (upload, list, policy, delete, tokens, distributions): the reason an
         * operator flips it is usually "a file went out that shouldn't have",
         * and they still need to inspect and delete it afterwards. Nor does it
         * replace the per-file [access_policy] — that stays the authentication
         * boundary; this is the "stop the tap" switch.
         *
         * Access policy enforcement (in order):
         *   - public       → no checks
         *   - api_key      → requires X-API-Key (checked HERE — the ApiKeyAuth
         *                    plugin allowlists this path for device downloads)
         *   - token        → requires X-Device-Id + X-Vault-Token matching
         *                    (configApiId, key, deviceId) triple
         *   - token_mtls   → same as token, plus verifies that the mTLS cert
         *                    CN matches the claimed deviceId
         *
         * If encryption == "end_to_end", the server wraps the content with
         * the device's RSA public key (see VaultEncryptionService); with
         * "user_auth", the same way with its user-auth key (412
         * `user_auth_key_required` when it registered none).
         *
         * A `token` / `token_mtls` file asked for with a valid token by a device
         * whose identity was revoked: 403 `reenroll_required` — after the token
         * check, so nobody without one learns which device ids were revoked.
         * Under a policy that authenticates nobody (`public`, `api_key`),
         * revocation plays no part: the answer depends only on whether a key
         * is on file for the device id (412 when not — revocation deleted the
         * device's keys), exactly as for an id that was never revoked.
         *
         * Nothing is decrypted before the request is authorised: existence,
         * the vault switch, the policy, the token, the 304 and the device-key
         * lookup are all decided from the file's metadata
         * ([VaultFileStore.meta]). Only a request that will be answered with
         * the file opens it. The content used to be read — and its at-rest
         * key derived, 200 000 PBKDF2 rounds — before the policy was looked
         * at, so a stranger asking for a token file made the server work for
         * 0.2 s to tell them 401.
         */
        get("/{key}") {
            if (!vaultEnabledProvider()) {
                log.warn("Vault download refused — vault disabled on configApi={} (key={})",
                    configApiId, call.pathParameters["key"])
                return@get call.respond(HttpStatusCode.Forbidden,
                    mapOf("error" to "Vault is disabled for Config API '$configApiId'"))
            }
            val key = call.pathParameters["key"]
                ?: return@get call.respond(HttpStatusCode.BadRequest, mapOf("error" to "Missing key"))
            // Defense-in-depth (L-02): vault keys are flat identifiers
            // (alphanumeric, `.`, `_`, `-`). The current storage backend is
            // SQLite with prepared statements so path traversal has no
            // direct effect, but if a future variant writes to disk this
            // check stops `..` segments before they reach the filesystem.
            if (!VAULT_KEY_REGEX.matches(key)) {
                return@get call.respond(HttpStatusCode.BadRequest,
                    mapOf("error" to "Invalid vault key format"))
            }

            val currentVersion = call.request.queryParameters["version"]?.toIntOrNull() ?: 0
            // Metadata only — see above. `entry` (the content) is read further down.
            val meta = vaultFileStore.meta(configApiId, key)
            val deviceId = call.request.header("X-Device-Id")
            if (meta == null) {
                // "No such file" is told only to a caller who showed who they
                // are: an admin key, or a client certificate (an mTLS listener).
                // Anyone else gets the answer a token-protected file gives the
                // same request, so asking for names does not reveal which files
                // exist behind a token. (A `public` file is public; an
                // `api_key` file still answers with its own 401 text.)
                val adminKey = call.request.header("X-API-Key")
                val known = call.clientCertId() != null || (adminKey != null &&
                    (ApiKeyPolicy.isNamedAdmin(adminKey) || apiKeyProvider()?.let { ApiKeyPolicy.matches(adminKey, it) } == true))
                if (known) return@get call.respond(HttpStatusCode.NotFound, mapOf("error" to "File not found: $key"))
                return@get call.respond(HttpStatusCode.Unauthorized, mapOf("error" to when {
                    deviceId.isNullOrBlank() -> "X-Device-Id header required for token policy"
                    call.request.header("X-Vault-Token") == null -> "X-Vault-Token header required"
                    else -> "Invalid or revoked token"
                }))
            }

            // Access policy check ────────────────────────────────────
            when (meta.accessPolicy) {
                "public" -> { /* no-op */ }
                "api_key" -> {
                    // The ApiKeyAuth plugin allowlists GET /api/v1/vault/{key}
                    // for every key (devices fetch public/token files without
                    // an admin key), so the plugin never checked this request.
                    // Enforce the key here; when no API_KEY is configured
                    // (ALLOW_ANONYMOUS_ADMIN dev mode) fail closed rather than
                    // turning an "admin-only" file into a world-readable one.
                    val expected = apiKeyProvider()
                    val provided = call.request.header("X-API-Key")
                    // A named admin (ADMIN_KEYS) may fetch it too, with or without API_KEY.
                    val namedAdmin = provided != null && ApiKeyPolicy.isNamedAdmin(provided)
                    if (expected == null && !namedAdmin && !ApiKeyPolicy.hasNamedAdmins()) {
                        log.warn("api_key file requested but no API_KEY configured: configApi={} key={}",
                            configApiId, key)
                        return@get call.respond(HttpStatusCode.Forbidden,
                            mapOf("error" to "api_key policy requires API_KEY to be configured on the server"))
                    }
                    if (!namedAdmin && (expected == null || !ApiKeyPolicy.matches(provided, expected))) {
                        log.warn("api_key file rejected (missing/invalid X-API-Key): configApi={} key={}",
                            configApiId, key)
                        return@get call.respond(HttpStatusCode.Unauthorized,
                            mapOf("error" to "X-API-Key header required for api_key policy"))
                    }
                }
                "token", "token_mtls" -> {
                    if (deviceId.isNullOrBlank()) {
                        return@get call.respond(HttpStatusCode.Unauthorized,
                            mapOf("error" to "X-Device-Id header required for token policy"))
                    }
                    val token = call.request.header("X-Vault-Token")
                        ?: return@get call.respond(HttpStatusCode.Unauthorized,
                            mapOf("error" to "X-Vault-Token header required"))

                    if (!tokenService.validate(configApiId, key, deviceId, token)) {
                        log.warn("Vault token rejected: configApi={} key={} deviceId={}",
                            configApiId, key, deviceId)
                        return@get call.respond(HttpStatusCode.Unauthorized,
                            mapOf("error" to "Invalid or revoked token"))
                    }

                    val certClientId = call.clientCertId()
                    if (meta.accessPolicy == "token_mtls") {
                        // The token alone proves "someone holds the secret".
                        // token_mtls additionally requires the request to
                        // arrive over a client-authenticated TLS connection
                        // whose certificate belongs to the same device, so a
                        // leaked token is useless without the private key.
                        if (certClientId == null) {
                            log.warn("token_mtls file requested without mTLS cert: configApi={} key={}",
                                configApiId, key)
                            return@get call.respond(HttpStatusCode.Unauthorized,
                                mapOf("error" to "mTLS client certificate required"))
                        }
                        // Proven, not claimed (V20): with a claim, a leaked token of
                        // the device plus any certificate that NAMED the device at
                        // enrollment opened the file — the private key token_mtls
                        // asks for would be anyone's.
                        if (!certificateProvenFor(certClientId, deviceId, clientCertStore)) {
                            log.warn("token_mtls deviceId/CN mismatch: certClientId={} claimed={}",
                                certClientId, deviceId)
                            return@get call.respond(HttpStatusCode.Unauthorized,
                                mapOf("error" to "Device identity mismatch"))
                        }
                    }
                    // The device's token (issued by an administrator for this
                    // device id) used over this certificate: the identity proved
                    // it acts for the device, so revoking it cuts the device off.
                    if (certClientId != null && certificateBoundTo(certClientId, deviceId, clientCertStore)) {
                        deviceProven(certClientId, deviceId, PROOF_TOKEN)
                    }
                    // A device whose identity an administrator revoked gets nothing
                    // that is meant for it alone, on any listener: revocation also
                    // revokes its tokens, but a token cached in a stolen app (or one
                    // revocation did not reach) stops working here at once. The same
                    // answer RevocationGate gives on mTLS, so the library re-enrolls —
                    // only to a caller who showed a valid token.
                    if (deviceRevoked(deviceId)) {
                        log.warn("Vault download refused — device {} belongs to a revoked identity: configApi={} key={}",
                            deviceId, configApiId, key)
                        return@get call.respondText(
                            """{"error":"reenroll_required","message":"This device's identity was revoked. Enroll again."}""",
                            ContentType.Application.Json, HttpStatusCode.Forbidden
                        )
                    }
                }
                else -> {
                    log.error("Unknown access_policy '{}' on {}:{}", meta.accessPolicy, configApiId, key)
                    return@get call.respond(HttpStatusCode.InternalServerError,
                        mapOf("error" to "Misconfigured access policy"))
                }
            }

            // 304 shortcut ───────────────────────────────────────────
            if (meta.version <= currentVersion) {
                call.response.header("X-Vault-Version", meta.version.toString())
                call.response.header("X-Vault-Encryption", meta.encryption)
                call.respond(HttpStatusCode.NotModified)
                return@get
            }

            // The device key an end_to_end / user_auth file is wrapped with,
            // looked up before the file is opened: no key, no decryption.
            // A key registered without a credential is on file for a revoked
            // device id like for any other (see the registration route): under
            // a policy that authenticated nobody the two get the same answer.
            val userAuth = meta.encryption == "user_auth"
            val deviceKey = if (meta.encryption in DEVICE_KEY_ENCRYPTIONS) {
                val did = deviceId ?: return@get call.respond(HttpStatusCode.Unauthorized,
                    mapOf("error" to "X-Device-Id required for ${meta.encryption} encryption"))
                (if (userAuth) userAuthKeyStore else publicKeyStore).get(did, configApiId)
                    ?: return@get call.respond(HttpStatusCode.PreconditionFailed, if (userAuth) mapOf(
                        "error" to "user_auth_key_required",
                        "message" to "No registered user-auth key for device; call POST /api/v1/vault/devices/{deviceId}/public-key with \"purpose\":\"user_auth\" first")
                    else mapOf(
                        "error" to "No registered public key for device; call POST /api/v1/vault/devices/{deviceId}/public-key first"))
            } else null
            // A user-auth key on file that this server would not accept today is
            // not sealed for: under USER_AUTH_ATTESTATION=enforce one registered
            // without a passing attestation (before enforce was switched on), and
            // under USER_AUTH_REQUIRE_PER_USE a time-bound one or one whose kind
            // was never read. 412 makes the library register again — with its
            // attestation chain, which settles it either way.
            if (userAuth && deviceKey != null) {
                userAuthKeyUnusable(deviceKey.attestation)?.let { reason ->
                    log.warn("User-auth file {}:{} not sealed for device {}: stored key {}", configApiId, key, deviceId, reason)
                    return@get call.respond(HttpStatusCode.PreconditionFailed, mapOf(
                        "error" to "user_auth_key_required",
                        "reason" to reason,
                        "message" to "The registered user-auth key cannot be used ($reason); register it again with its attestationChain " +
                            "(POST /api/v1/vault/devices/{deviceId}/public-key, \"purpose\":\"user_auth\")"))
                }
            }
            if (meta.encryption !in VALID_ENCRYPTIONS) {
                // A value no branch below knows must never go out as
                // plaintext; uploads refuse unknown values, so this is a
                // row written some other way.
                log.error("Unknown encryption '{}' on {}:{} — not served", meta.encryption, configApiId, key)
                return@get call.respond(HttpStatusCode.InternalServerError,
                    mapOf("error" to "Misconfigured encryption on this file; it is not served"))
            }

            // Authorised, and a body will be sent: only now is the file opened —
            // at most a few at once per source address (a public file asks for
            // nothing, and each answer is the whole file).
            val slotKey = com.example.pinvault.server.service.RateLimiter.sourceKey(call.request.origin.remoteAddress)
            if (downloadSlots?.tryAcquire(slotKey) == false) {
                call.response.header(HttpHeaders.RetryAfter, "1")
                return@get call.respond(HttpStatusCode.TooManyRequests,
                    mapOf("error" to "rate_limited", "message" to "Too many downloads at once from this address. Try again."))
            }
            if (downloadSlotsTotal?.tryAcquire(TOTAL_SLOT_KEY) == false) {
                downloadSlots?.release(slotKey)
                call.response.header(HttpHeaders.RetryAfter, "1")
                return@get call.respond(HttpStatusCode.TooManyRequests,
                    mapOf("error" to "rate_limited", "message" to "Too many downloads at once. Try again."))
            }
            try {
                val entry = vaultFileStore.get(configApiId, key)
                    ?: return@get call.respond(HttpStatusCode.NotFound, mapOf("error" to "File not found: $key"))
                if (entry.accessPolicy != meta.accessPolicy || entry.encryption != meta.encryption) {
                    // Changed by an administrator between the two reads: what was
                    // checked above no longer covers it. The device asks again.
                    call.response.header(HttpHeaders.RetryAfter, "1")
                    return@get call.respond(HttpStatusCode.ServiceUnavailable,
                        mapOf("error" to "file_changed", "message" to "The file changed while it was being served. Ask again."))
                }

                // Encryption ─────────────────────────────────────────────
                val payload: ByteArray = when (entry.encryption) {
                    "plain", "at_rest" -> entry.content
                    // end_to_end: wrapped with the device's E2E key. user_auth: the same
                    // envelope and code path with the device's USER-AUTH key, whose
                    // private half the phone's hardware uses only after the user
                    // unlocked — a rooted device calling this API without the user
                    // gets ciphertext only.
                    "end_to_end", "user_auth" -> {
                        val did = deviceId
                        val pubKey = deviceKey!!
                        try {
                            // Wrapped with the MGF1 hash the key was registered with (Android SHA-1, iOS SHA-256).
                            encryptionService.encryptForDevice(entry.content, pubKey.publicKeyPem, pubKey.algorithm)
                        } catch (e: Exception) {
                            // The cause goes to the log under an id, never to the caller.
                            val errorId = java.util.UUID.randomUUID().toString().take(8)
                            log.error("Encryption failed {}: configApi={} key={} deviceId={}",
                                errorId, configApiId, key, did, e)
                            return@get call.respond(HttpStatusCode.InternalServerError,
                                mapOf("error" to "Encryption failed", "errorId" to errorId))
                        }
                    }
                    else -> {
                        // A value no branch above knows must never go out as
                        // plaintext; uploads refuse unknown values, so this is a
                        // row written some other way.
                        log.error("Unknown encryption '{}' on {}:{} — not served", entry.encryption, configApiId, key)
                        return@get call.respond(HttpStatusCode.InternalServerError,
                            mapOf("error" to "Misconfigured encryption on this file; it is not served"))
                    }
                }

                call.response.header("X-Vault-Version", entry.version.toString())
                call.response.header("X-Vault-Encryption", entry.encryption)
                // Integrity (default-on): sign the PLAINTEXT (entry.content), not the
                // possibly per-device-encrypted wire `payload`, so a single signature
                // covers plain/at_rest/end_to_end and the device verifies whatever
                // plaintext it ends up with. Canonical binds key+version+hash.
                // With several signers (m-of-n) every signature goes into
                // X-Vault-Signatures as `keyId:signature`, comma-separated;
                // X-Vault-Signature keeps the primary one for older clients.
                //
                // v2 (`X-Vault-Signature-V2`, `X-Vault-Signatures-V2`, same encoding)
                // signs `pinvault-vault-file:v2:<configApiId>:<key>:<version>:<sha256>`:
                // it names this Config API, so a file signed for another Config API with
                // the same key does not pass on a block that set `serverScope`. v1 stays
                // for older clients.
                vaultSigner?.let {
                    val signatures = try {
                        // An external signer may take seconds: off the event loop.
                        kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) { it.vaultSignatures(configApiId, key, entry.version, entry.content) }
                    } catch (e: Exception) {
                        // Never hand signer internals to the caller; a busy signer is a 503 like the config endpoint's.
                        log.warn("Vault file signing failed for {}:{}: {}", configApiId, key, e.message)
                        return@get call.respond(HttpStatusCode.ServiceUnavailable, mapOf("error" to "File signing is temporarily unavailable"))
                    }
                    call.response.header("X-Vault-Signature", signatures.v1.first().signature)
                    if (signatures.v1.size > 1) {
                        call.response.header(
                            "X-Vault-Signatures",
                            signatures.v1.joinToString(",") { s -> "${s.keyId}:${s.signature}" }
                        )
                    }
                    call.response.header(VAULT_SIGNATURE_V2_HEADER, signatures.v2.first().signature)
                    call.response.header(
                        VAULT_SIGNATURES_V2_HEADER,
                        signatures.v2.joinToString(",") { s -> "${s.keyId}:${s.signature}" }
                    )
                }
                call.respondBytes(payload, ContentType.Application.OctetStream)
            } finally {
                downloadSlotsTotal?.release(TOTAL_SLOT_KEY)
                downloadSlots?.release(slotKey)
            }
        }

        /**
         * Register / update a device's public key for E2E encryption — or,
         * with `"purpose":"user_auth"`, its USER-AUTH key (`user_auth` files),
         * stored apart from the E2E key under the same rules below.
         *
         * Who may set the key of `{deviceId}` (audit M-2 — it used to be
         * anyone who could reach the port, so a stranger could swap in a key
         * and read what the server then encrypted "for" the device):
         *  - a client certificate was presented (mTLS listener): only one
         *    bound to that device ([certificateBoundTo]). It replaces a key
         *    with the certificate alone only when the device id is PROVEN
         *    ([certificateProvenFor]: attested, bound to the token by an
         *    administrator, or the client id itself); otherwise as on TLS;
         *  - no certificate (TLS listener): the first key is accepted and the
         *    same key again is a no-op. Replacing a registered key needs proof
         *    that the operator handed this device out — a valid vault token,
         *    bound to `{deviceId}`, for an end_to_end file of this scope
         *    (`X-Vault-Key` + `X-Vault-Token`; the library sends it). Without
         *    one: 409, and the registered key stays.
         *
         * Residual on TLS: whoever registers first for a device id that never
         * registered holds the slot until the device shows proof or an
         * administrator removes the key (DELETE below). Files that matter
         * belong on an mTLS Config API.
         *
         * A USER-AUTH key is held to more (`USER_AUTH_ATTESTATION`). Replacing
         * a registered one needs BOTH the device's credential (a client
         * certificate bound to it, or its token for an end_to_end / user_auth
         * file) AND a new key whose Android Key Attestation chain passes
         * ([AndroidKeyAttestation]: hardware-backed, needs the user, made by the
         * app — package AND signer configured — on a locked device for this
         * device id); otherwise 409 `user_auth_key_exists` with `reason`
         * `credential_required`, `attestation_off` or the attestation's reason.
         * Root code running as the app holds the credential but cannot make an
         * attestation for a key it controls; a stranger can attest a key on a
         * phone of their own but has no credential. `off` never replaces (an
         * administrator resets the key). A first key: `enforce` needs a passing
         * chain (403 `attestation_required` / `attestation_invalid`); `warn`
         * and `off` accept it without any credential (trust on first use) and
         * `warn` stores the outcome with it. The body carries the chain as
         * `attestationChain` (Base64 DER, leaf first).
         *
         * An iPhone has no such chain: with App Attest configured ([appAttest])
         * a user-auth key sent without `attestationChain` but with
         * `appAttestation` — a fresh App Attest key's attestation with client
         * data hash SHA-256 of `pinvault-user-auth-key:v1:<deviceId>:<base64
         * SHA-256 of the key's SPKI DER>` — is judged by that instead, under
         * the same rules (first key, replacement, enforce). A pass is stored as
         * key kind `app_attest`: the server cannot read the key's access
         * control from it, only that the genuine app on Apple hardware sent it.
         *
         * A device whose identity was revoked: an authenticated request (bound
         * certificate or token proof; an attestation does not count) gets 403
         * `reenroll_required`. A request without a credential is handled as
         * for any other device id — first key kept, a different one 409 — so
         * strangers cannot ask which ids were revoked. (It used to be answered
         * 200 and not stored: a second, different key then got 200 where any
         * other id answers 409, and a `public` end_to_end file 412 where any
         * other id gets the file — which told exactly that.) Revocation still
         * deleted the device's keys and tokens and still refuses its
         * certificate and its tokens; a key registered afterwards without a
         * credential opens only what any stranger with a made-up device id
         * can open, files whose policy authenticates nobody.
         *
         * Nothing here asks for a credential on TLS, so a key is only stored
         * when the server could encrypt for it (RSA 2048–4096, re-encoded),
         * a source address writes at most [keyLimiter]'s quota of keys (a
         * caller without a credential is counted before its chain is
         * verified), and a scope holds at most [maxDeviceKeys] of them.
         */
        post("/devices/{deviceId}/public-key") {
            val deviceId = call.pathParameters["deviceId"]
                ?: return@post call.respond(HttpStatusCode.BadRequest, mapOf("error" to "Missing deviceId"))
            // Printed in the dashboard and the audit log, matched against X-Device-Id.
            if (!isValidIdentifier(deviceId)) {
                return@post call.respond(HttpStatusCode.BadRequest, mapOf(
                    "error" to "invalid_device_id",
                    "message" to "Letters, digits, '.', '_', ':' and '-' only, at most 64."))
            }
            val body = call.receiveLimitedJson() ?: return@post
            val pem = body.string("publicKeyPem")
                ?: return@post call.respond(HttpStatusCode.BadRequest,
                    mapOf("error" to "publicKeyPem field required"))
            // Absent or "e2e": the E2E key. "user_auth": the key the phone uses
            // only after the user unlocked, kept apart (neither overwrites the other).
            val purpose = body.string("purpose") ?: PURPOSE_E2E
            if (purpose != PURPOSE_E2E && purpose != PURPOSE_USER_AUTH) {
                return@post call.respond(HttpStatusCode.BadRequest, mapOf(
                    "error" to "unsupported_purpose",
                    "message" to "purpose must be \"e2e\" or \"user_auth\"."))
            }
            val userAuth = purpose == PURPOSE_USER_AUTH
            val keyStore = if (userAuth) userAuthKeyStore else publicKeyStore
            val what = if (userAuth) "User-auth key" else "E2E key"
            // How files are wrapped for this key: the MGF1 hash differs per platform
            // (Android MGF1-SHA1, the default; iOS MGF1-SHA256), so it is stored with it.
            val algorithm = body.string("algorithm") ?: com.example.pinvault.server.service.VaultEncryptionService.RSA_OAEP_SHA256
            if (algorithm !in com.example.pinvault.server.service.VaultEncryptionService.ALGORITHMS) {
                return@post call.respond(HttpStatusCode.BadRequest, mapOf(
                    "error" to "unsupported_algorithm",
                    "message" to "algorithm must be RSA-OAEP-SHA256 (SHA-256 with MGF1-SHA1, Android; the default) " +
                        "or RSA-OAEP-SHA256-MGF1-SHA256 (SHA-256 with MGF1-SHA256, iOS)."))
            }
            val parsedKey = parseDeviceRsaKey(pem)
                ?: return@post call.respond(HttpStatusCode.BadRequest, mapOf(
                    "error" to "invalid_public_key",
                    "message" to "publicKeyPem must be an RSA public key of 2048 to 4096 bits (X.509 SubjectPublicKeyInfo)."))
            val key = canonicalPem(parsedKey)
            val remote = call.request.origin.remoteAddress

            val certClientId = call.clientCertId()
            if (certClientId != null && !certificateBoundTo(certClientId, deviceId, clientCertStore)) {
                keyRefusals?.report(remote, "POST", call.request.path(), actor = certClientId,
                    reason = "certificate not bound to device $deviceId")
                return@post call.respond(HttpStatusCode.Forbidden, mapOf(
                    "error" to "device_identity_mismatch",
                    "message" to "The client certificate does not belong to device $deviceId."))
            }
            val existing = keyStore.get(deviceId, configApiId)
            // The same key under another algorithm is a change too: files would be wrapped differently.
            val changed = existing == null || !samePublicKey(existing.publicKeyPem, key) || existing.algorithm != algorithm

            // The device's token for a file wrapped with a device key: an
            // end_to_end file for the E2E key; end_to_end or user_auth for
            // the user-auth key.
            val proofEncryptions = if (userAuth) DEVICE_KEY_ENCRYPTIONS else setOf("end_to_end")
            val proofKey = call.request.header("X-Vault-Key")?.trim()
            val proofToken = call.request.header("X-Vault-Token")?.trim()
            // Looked up only when a decision needs it. The file's metadata is
            // all it takes: this used to open the file — a key derivation for
            // every request that named one, with any token, from anyone.
            val tokenProven by lazy(LazyThreadSafetyMode.NONE) {
                !proofKey.isNullOrEmpty() && !proofToken.isNullOrEmpty() && VAULT_KEY_REGEX.matches(proofKey) &&
                    vaultFileStore.meta(configApiId, proofKey)?.encryption in proofEncryptions &&
                    tokenService.validate(configApiId, proofKey, deviceId, proofToken)
            }

            // The device's own credential: a client certificate PROVEN to be its
            // (V20: attested, bound by an administrator, or the device id as the
            // client id) or its vault token. A certificate whose enrollment only
            // named the device id is not one: anyone with a token or code who
            // knows a victim's ANDROID_ID could otherwise replace its keys.
            val certProven = certClientId != null && certificateProvenFor(certClientId, deviceId, clientCertStore)
            val credentialed = certProven || tokenProven

            // Revocation, decided only after the request authenticated: a revoked
            // device keeps no keys (revocation deleted them) and gets none back
            // until it enrolled again. The clear signal goes to a caller with the
            // device's credential — never to one with only an attestation, which
            // anyone with a phone of their own can make for any device id. Anyone
            // else is handled below exactly as for any device id (first key kept,
            // a different one refused), so no answer says which ids were revoked.
            val revoked = deviceRevoked(deviceId)
            if (revoked && credentialed) {
                keyRefusals?.report(remote, "POST", call.request.path(), actor = certClientId ?: deviceId, reason = "device identity revoked")
                return@post call.respondText(
                    """{"error":"reenroll_required","message":"This device's identity was revoked. Enroll again."}""",
                    ContentType.Application.Json, HttpStatusCode.Forbidden
                )
            }

            // Android Key Attestation of a user-auth key (not checked when off),
            // verified only when its outcome decides or records something: a first
            // key, a replacement by the device's own credential, or the same key
            // not attested yet. A replacement without a credential is refused below
            // without looking at the chain.
            val mode = userAuthAttestationMode
            val needsVerdict = userAuth && mode != com.example.pinvault.server.service.UserAuthAttestationMode.OFF && when {
                existing == null -> true
                changed -> credentialed
                // Not attested yet, or attested before the key's kind was read:
                // the same key with its chain settles it.
                else -> existing.attestation?.attested != true || existing.attestation.keyKind == null
            }
            val chainElement = body["attestationChain"]
            // An iPhone's App Attest in place of the chain: configured, no chain sent
            // (absent, null or empty) and an `appAttestation` in the body.
            val appAttestElement = body[com.example.pinvault.server.service.attestation.AppAttestAdmission.FIELD]?.takeIf { it !is JsonNull }
            val viaAppAttest = userAuth && appAttest != null && appAttestElement != null &&
                (chainElement == null || chainElement is JsonNull || (chainElement is JsonArray && chainElement.isEmpty()))
            // Verifying a chain costs signature checks, and over TLS anyone may ask:
            // a caller without a credential is counted BEFORE it (and not again below).
            var counted = false
            if (needsVerdict && ((chainElement is JsonArray && chainElement.isNotEmpty()) || viaAppAttest) && !credentialed && keyLimiter != null) {
                counted = true
                if (!keyLimiter.allow(com.example.pinvault.server.service.RateLimiter.sourceKey(remote))) {
                    keyRefusals?.report(remote, "POST", call.request.path(), actor = deviceId, reason = "rate limited")
                    return@post call.respond(HttpStatusCode.TooManyRequests, mapOf(
                        "error" to "rate_limited",
                        "message" to "Too many key registrations from this address. Try again later."))
                }
            }
            val verdict: com.example.pinvault.server.service.AndroidKeyAttestation.Verdict? =
                if (!needsVerdict) null
                else if (viaAppAttest) {
                    // Bound to this device id and this key: one made for another key or device fails nonce_mismatch.
                    val clientDataHash = com.example.pinvault.server.service.attestation.AppAttestAdmission.userAuthClientDataHash(deviceId, parsedKey.encoded)
                    when (val r = com.example.pinvault.server.service.attestation.AppAttestAdmission.verify(appAttest!!, appAttestElement, clientDataHash)) {
                        is com.example.pinvault.server.service.attestation.AppAttestAdmission.Result.Passed ->
                            com.example.pinvault.server.service.AndroidKeyAttestation.Verdict(true, com.example.pinvault.server.service.attestation.AppAttestAdmission.KIND)
                        is com.example.pinvault.server.service.attestation.AppAttestAdmission.Result.Failed ->
                            com.example.pinvault.server.service.AndroidKeyAttestation.Verdict(false, r.reason)
                        com.example.pinvault.server.service.attestation.AppAttestAdmission.Result.Absent ->
                            com.example.pinvault.server.service.AndroidKeyAttestation.Verdict.MISSING
                    }
                } else when (chainElement) {
                    null, JsonNull -> com.example.pinvault.server.service.AndroidKeyAttestation.Verdict.MISSING
                    is JsonArray -> {
                        val entries = chainElement.map { (it as? JsonPrimitive)?.takeIf { p -> p.isString }?.content }
                        if (entries.any { it == null }) com.example.pinvault.server.service.AndroidKeyAttestation.Verdict(false, "chain_malformed")
                        else attestation.verify(entries.filterNotNull(), parsedKey, deviceId)
                    }
                    else -> com.example.pinvault.server.service.AndroidKeyAttestation.Verdict(false, "chain_malformed")
                }.let { v ->
                    // Without the package + signer binding a passing chain says nothing
                    // about which app made the key (any app can use any device id's
                    // challenge): it never counts.
                    if (v.passed && !attestation.bindsApp) com.example.pinvault.server.service.AndroidKeyAttestation.Verdict(false, APP_BINDING_NOT_CONFIGURED, v.securityLevel)
                    else v
                }
            val attested = verdict?.passed == true
            val attestationNote = verdict?.let {
                when {
                    it.passed && viaAppAttest -> "admitted by App Attest"
                    it.passed -> "attested: ${it.securityLevel}"
                    viaAppAttest -> "App Attest: ${it.reason}"
                    else -> "attestation: ${it.reason}"
                }
            } ?: "attestation not checked"
            // What a refusal names: the chain, or — with App Attest configured — either.
            val attestationWord = if (appAttest != null) "Android Key Attestation (or, from an iOS app, App Attest attestation)" else "Android Key Attestation"

            if (userAuth) {
                if (existing != null && changed) {
                    // A replacement needs BOTH the device's credential and a passing
                    // attestation. Root code running as the app holds the credential;
                    // a stranger with a phone of their own can make an attestation for
                    // any device id. Neither alone replaces the key.
                    val refusal = when {
                        !credentialed -> "credential_required"
                        mode == com.example.pinvault.server.service.UserAuthAttestationMode.OFF -> "attestation_off"
                        !attested -> verdict?.reason ?: com.example.pinvault.server.service.AndroidKeyAttestation.Verdict.MISSING.reason
                        else -> null
                    }
                    if (refusal != null) {
                        keyRefusals?.report(remote, "POST", call.request.path(), actor = certClientId ?: deviceId,
                            reason = "user-auth key replacement refused ($refusal; $attestationNote)")
                        return@post call.respondText(buildJsonObject {
                            put("error", "user_auth_key_exists")
                            put("reason", refusal)
                            put("message", "A user-auth key is already registered for this device. It is replaced only by a key " +
                                "whose $attestationWord passes, sent with the device's client certificate or vault token" +
                                (if (mode == com.example.pinvault.server.service.UserAuthAttestationMode.OFF) " (attestation is not checked on this server)" else "") +
                                ", or after an administrator removed the old one.")
                        }.toString(), ContentType.Application.Json, HttpStatusCode.Conflict)
                    }
                }
                // Under enforce a key without a passing attestation is refused: a first
                // one, and the key on file sent again (one registered before enforce,
                // or under rules it no longer meets) — the device makes a new key.
                if ((existing == null || !changed) && verdict != null &&
                    mode == com.example.pinvault.server.service.UserAuthAttestationMode.ENFORCE && !attested) {
                    val missing = verdict.reason == com.example.pinvault.server.service.AndroidKeyAttestation.Verdict.MISSING.reason
                    keyRefusals?.report(remote, "POST", call.request.path(), actor = certClientId ?: deviceId,
                        reason = "user-auth key refused under USER_AUTH_ATTESTATION=enforce ($attestationNote)")
                    return@post call.respondText(buildJsonObject {
                        if (missing) {
                            put("error", "attestation_required")
                            put("message", "This server needs the key's Android Key Attestation chain (attestationChain)" +
                                (if (appAttest != null) " or, from an iOS app, an App Attest attestation of the key (appAttestation)." else "."))
                        } else {
                            put("error", "attestation_invalid")
                            put("reason", verdict.reason)
                            put("message", "The key's ${if (viaAppAttest) "App Attest attestation" else "Android Key Attestation"} did not pass: ${verdict.reason}.")
                        }
                    }.toString(), ContentType.Application.Json, HttpStatusCode.Forbidden)
                }
            } else if (existing != null && changed && !tokenProven && !certProven) {
                // Over mTLS as over TLS: a certificate that only claims the device
                // is no proof.
                keyRefusals?.report(remote, "POST", call.request.path(), actor = certClientId ?: deviceId,
                    reason = "${what.lowercase()} change without proof")
                return@post call.respond(HttpStatusCode.Conflict, mapOf(
                    "error" to "key_change_requires_proof",
                    "message" to "A different key is already registered for this device. Replacing it " +
                        "needs the device's token for an ${proofEncryptions.joinToString(" or ")} file (X-Vault-Key + X-Vault-Token), a client " +
                        "certificate whose device id is proven (an attested key, or a token an administrator bound to the device), " +
                        "or an administrator removing the old key."))
            }
            // A device replaces its key after its data was cleared, not in a loop:
            // per identity, so a certificate cannot alternate keys and write an
            // audit entry and a webhook each time.
            if (existing != null && changed && certClientId != null &&
                keyReplacementLimiter?.allow("key|$certClientId") == false) {
                keyRefusals?.report(remote, "POST", call.request.path(), actor = certClientId, reason = "key replacements rate limited")
                return@post call.respond(HttpStatusCode.TooManyRequests, mapOf(
                    "error" to "rate_limited",
                    "message" to "Too many key replacements for this identity. Try again later."))
            }

            if (changed) {
                // A device writes its key once, and again only after its data
                // was cleared; a source writing many is making them up.
                if (certClientId == null && !counted && keyLimiter?.allow(com.example.pinvault.server.service.RateLimiter.sourceKey(remote)) == false) {
                    keyRefusals?.report(remote, "POST", call.request.path(), actor = deviceId, reason = "rate limited")
                    return@post call.respond(HttpStatusCode.TooManyRequests, mapOf(
                        "error" to "rate_limited",
                        "message" to "Too many key registrations from this address. Try again later."))
                }
                if (existing == null && keyStore.count(configApiId) >= maxDeviceKeys) {
                    log.error("{} of device {} refused: configApi={} already holds {} device keys (DEVICE_KEY_LIMIT)",
                        what, deviceId, configApiId, maxDeviceKeys)
                    keyRefusals?.report(remote, "POST", call.request.path(), actor = deviceId, reason = "device key limit reached")
                    return@post call.respond(HttpStatusCode.ServiceUnavailable, mapOf(
                        "error" to "device_key_limit_reached",
                        "message" to "This server stores no more device keys. Ask an administrator."))
                }
            }

            val accepted = mapOf("registered" to "true", "deviceId" to deviceId, "purpose" to purpose)

            // A key registered over the certificate proves the identity acts for this
            // device only with more than the certificate: the device's token in the
            // same request. A certificate is "bound" to a device id by a mere claim
            // at enrollment, and a key proves nothing — a new one, this identity's
            // own again, or the device's existing key sent back (a PUBLIC key:
            // anyone can resend it; that used to count). Otherwise someone who
            // enrolled naming a victim's id would "prove" it, and revoking them
            // would cut the victim off.
            if (certClientId != null && certClientId != deviceId && tokenProven) {
                deviceProven(certClientId, deviceId, PROOF_KEY)
            }

            // What attestation said, stored with a user-auth key: with a passing
            // one, how the key asks for the user (per use / time-bound, biometric
            // only). The same key sent again WITHOUT its chain keeps a passing
            // result it already had; with a chain that now fails (a time-bound
            // key under USER_AUTH_REQUIRE_PER_USE, a revoked certificate) it is
            // no longer attested.
            val record = when {
                !userAuth -> null
                verdict == null -> if (changed) null else existing?.attestation
                // App Attest: kind app_attest — how the key asks for the user is not known to the server.
                verdict.passed && viaAppAttest -> com.example.pinvault.server.service.attestation.AppAttestAdmission.record()
                verdict.passed -> com.example.pinvault.server.store.KeyAttestation(
                    true, verdict.securityLevel, verdict.reason,
                    keyKind = verdict.keyKind?.name,
                    authTimeoutSeconds = verdict.keyKind?.timeoutSeconds,
                    biometricOnly = verdict.keyKind?.biometricOnly
                )
                !changed && existing?.attestation?.attested == true &&
                    verdict.reason == com.example.pinvault.server.service.AndroidKeyAttestation.Verdict.MISSING.reason -> existing.attestation
                else -> com.example.pinvault.server.store.KeyAttestation(false, verdict.securityLevel, verdict.reason)
            }
            keyStore.register(deviceId, configApiId, key, algorithm, Instant.now().toString(), attestation = record)
            val attestationDetail: JsonObject? = if (!userAuth) null else buildJsonObject {
                put("purpose", PURPOSE_USER_AUTH)
                put("attestationMode", userAuthAttestationMode.name.lowercase())
                if (verdict != null) {
                    put("attested", verdict.passed)
                    put("attestationReason", verdict.reason)
                    verdict.securityLevel?.let { put("securityLevel", it) }
                    if (viaAppAttest) put("attestedBy", com.example.pinvault.server.service.attestation.AppAttestAdmission.KIND)
                }
            }
            if (changed) {
                val replaced = existing != null
                audit?.record(
                    if (replaced) "device_key_replaced" else "device_key_registered",
                    "$what of device $deviceId ${if (replaced) "replaced" else "registered"}" +
                        (certClientId?.let { " over the certificate of $it" } ?: "") +
                        // Only an unauthenticated request gets here for such a device; the
                        // administrator reads it here, the caller is told nothing.
                        (if (revoked) " — without a credential, for a device id whose identity was revoked" else "") +
                        (if (userAuth) " ($attestationNote${if (!replaced && verdict != null && !verdict.passed) "; accepted on first use" else ""})" else "") +
                        (if (algorithm != com.example.pinvault.server.service.VaultEncryptionService.RSA_OAEP_SHA256) ", $algorithm" else ""),
                    configApiId, deviceId, actor = certClientId ?: deviceId, ip = remote,
                    detail = attestationDetail
                )
            } else if (userAuth && attested && existing?.attestation?.attested != true) {
                audit?.record("device_key_attested", "User-auth key of device $deviceId now attested ($attestationNote)",
                    configApiId, deviceId, actor = certClientId ?: deviceId, ip = remote, detail = attestationDetail)
            }
            call.respond(HttpStatusCode.OK, accepted)
        }

        /**
         * Client reports a vault file download.
         *
         * No credential is asked for on a TLS listener (a device that cannot
         * authenticate is the one whose report matters), so every field is the
         * sender's claim and none is stored as it comes (audit M-3 / O15): the
         * key and the device id must have their shape, status and authMethod
         * come from a fixed list, names and the failure reason are cut to a
         * printable line, the time is the server's. Reports are counted per
         * source address and per device ([reportLimits]), and the history is
         * trimmed per Config API with failures kept apart (the store) — it
         * used to be one table-wide window of 500 rows, which 500 made-up
         * reports turned over for every scope.
         *
         * On an mTLS listener the report must be about the certificate's own
         * device ([certificateBoundTo]): 403 `device_identity_mismatch`
         * otherwise. A report without a device id is filed under the
         * certificate's device there, and under `unknown` on TLS.
         */
        post("/report") {
            if (!call.reportAllowedFromAddress(reportLimits)) return@post
            val body = call.receiveLimitedJson() ?: return@post
            val key = body.string("key").orEmpty()
            if (!VAULT_KEY_REGEX.matches(key)) {
                return@post call.respondInvalidReport("key", "A vault file key: letters, digits, '.', '_' and '-', at most 64.")
            }
            val version = body.int("version") ?: 0
            if (version < 0) return@post call.respondInvalidReport("version", "Not negative.")
            val status = body.string("status") ?: "downloaded"
            if (status !in VaultDistributionStore.REPORT_STATUSES) {
                return@post call.respondInvalidReport("status", "One of ${VaultDistributionStore.REPORT_STATUSES.joinToString()}.")
            }
            val authMethod = body.string("authMethod")
            if (authMethod != null && authMethod !in REPORT_AUTH_METHODS) {
                return@post call.respondInvalidReport("authMethod", "One of ${REPORT_AUTH_METHODS.joinToString()}.")
            }
            val reportedId = body.string("deviceId")
            if (reportedId != null && !isValidIdentifier(reportedId)) {
                return@post call.respondInvalidReport("deviceId", "Letters, digits, '.', '_', ':' and '-' only, at most 64.")
            }
            // The certificate is the device's identity on an mTLS listener: it
            // reports for itself only.
            val certClientId = call.clientCertId()
            if (certClientId != null && reportedId != null && !certificateBoundTo(certClientId, reportedId, clientCertStore)) {
                log.warn("Vault report refused — certificate of {} is not bound to device {}: configApi={}",
                    certClientId, reportedId, configApiId)
                return@post call.respond(HttpStatusCode.Forbidden, mapOf(
                    "error" to "device_identity_mismatch",
                    "message" to "The client certificate does not belong to device $reportedId."))
            }
            val deviceId = reportedId
                ?: certClientId?.let { clientCertStore?.get(it)?.deviceUid ?: it }
                ?: "unknown"
            // Per device only where the device id is backed by a certificate. On TLS
            // it is the sender's word: counted per device, anyone could use up a
            // victim's quota and suppress its reports. The address was counted above.
            if (certClientId != null && !call.reportAllowedForDevice(reportLimits, configApiId, certClientId)) return@post

            distStore.add(configApiId, key, version, deviceId,
                manufacturer = displayAlias(body.string("deviceManufacturer")),
                model = displayAlias(body.string("deviceModel")),
                enrollmentLabel = displayAlias(body.string("enrollmentLabel")),
                status = status,
                timestamp = Instant.now().toString(),
                deviceAlias = displayAlias(body.string("deviceAlias")),
                failureReason = reportText(body.string("failureReason")),
                authMethod = authMethod)
            call.respond(HttpStatusCode.OK, mapOf("recorded" to "true"))
        }
    }
}

/** Every `access_policy` a vault file may carry; the download route enforces each one. */
internal val VALID_POLICIES = setOf("public", "api_key", "token", "token_mtls")

/** Every `encryption` a vault file may carry; anything else is refused at upload and never served. */
internal val VALID_ENCRYPTIONS = setOf("plain", "at_rest", "end_to_end", "user_auth")

/**
 * Why an upload of [key] with `?policy=` [policy] and `?encryption=`
 * [encryption] must be refused, or null when it may be stored (a null
 * policy/encryption keeps the file's current value, or the default).
 *
 * Both values are shown in the dashboard and decide how the file is
 * served: they used to be stored as sent, so `?policy=<button …>` became
 * markup in another admin's vault tab, and an unknown encryption was served
 * as plaintext.
 */
internal fun vaultUploadError(key: String, policy: String?, encryption: String?): String? = when {
    // A key must also not collide with a constant admin/report segment
    // (`distributions`, `stats`, …) — Ktor would route its download to that
    // handler and ApiKeyAuth treats those as admin.
    !VAULT_KEY_REGEX.matches(key) || key in RESERVED_VAULT_SEGMENTS -> "Invalid vault key format"
    policy != null && policy !in VALID_POLICIES -> "Invalid access_policy; one of ${VALID_POLICIES.joinToString()}"
    encryption != null && encryption !in VALID_ENCRYPTIONS -> "Invalid encryption; one of ${VALID_ENCRYPTIONS.joinToString()}"
    else -> null
}

/**
 * Whether two PEMs carry the same key: compared on the Base64 body, so line
 * breaks and header spelling do not turn a device's own key into a "change".
 */
private fun samePublicKey(a: String, b: String): Boolean = pemBody(a) == pemBody(b)

private fun pemBody(pem: String) = pem.lineSequence().filterNot { it.trim().startsWith("-----") }
    .joinToString("").filterNot { it.isWhitespace() }

/**
 * The key in [pem] when end_to_end files can be encrypted for it: RSA of 2048
 * to 4096 bits as X.509 SubjectPublicKeyInfo. Null for anything else.
 */
private fun parseDeviceRsaKey(pem: String): java.security.interfaces.RSAPublicKey? {
    val key = try {
        java.security.KeyFactory.getInstance("RSA")
            .generatePublic(java.security.spec.X509EncodedKeySpec(java.util.Base64.getDecoder().decode(pemBody(pem))))
            as? java.security.interfaces.RSAPublicKey
    } catch (_: Exception) {
        null
    } ?: return null
    return key.takeIf { it.modulus.bitLength() in 2048..4096 }
}

/** [key] as PEM, the way the library writes it. */
private fun canonicalPem(key: java.security.PublicKey): String {
    val body = java.util.Base64.getEncoder().encodeToString(key.encoded).chunked(64).joinToString("\n")
    return "-----BEGIN PUBLIC KEY-----\n$body\n-----END PUBLIC KEY-----"
}

/** How an identity proved it acts for a device (`identity_devices.proof`). */
/** The single key of the total download limiter (`VAULT_DOWNLOAD_CONCURRENCY_TOTAL`). */
private const val TOTAL_SLOT_KEY = "*"
private const val PROOF_KEY = "key_over_certificate"
private const val PROOF_TOKEN = "token_over_certificate"

/** A user-auth attestation that passed but cannot count: no package + signer binding configured. */
private const val APP_BINDING_NOT_CONFIGURED = "app_binding_not_configured"

/** v2 vault signature headers (the library's `VAULT_SIGNATURE_V2_HEADER` / `VAULT_SIGNATURES_V2_HEADER`). */
const val VAULT_SIGNATURE_V2_HEADER = "X-Vault-Signature-V2"
const val VAULT_SIGNATURES_V2_HEADER = "X-Vault-Signatures-V2"

/** 412 `user_auth_key_required` reasons: the key on file is not sealed for (see the download route). */
internal const val KEY_NOT_ATTESTED = "key_not_attested"
internal const val TIME_BOUND_KEY = "time_bound_key"
internal const val KEY_KIND_UNKNOWN = "key_kind_unknown"

/** Allowed vault-key shape — alphanumeric plus `.`, `_`, `-`, 1-64 chars. */
private val VAULT_KEY_REGEX = Regex("^[A-Za-z0-9._-]{1,64}$")

/** `VAULT_MAX_FILE_BYTES` when unset: 50 MB. */
const val DEFAULT_VAULT_MAX_FILE_BYTES: Long = 50L * 1024 * 1024

/** How a device says it authenticated a download (`authMethod` of a report): the access policies. */
private val REPORT_AUTH_METHODS = VALID_POLICIES

/** Encryptions that wrap a file with one device's key: refused to a revoked device. */
private val DEVICE_KEY_ENCRYPTIONS = setOf("end_to_end", "user_auth")

/** What a registered device key is for (`purpose`): absent = "e2e". */
private const val PURPOSE_E2E = "e2e"
private const val PURPOSE_USER_AUTH = "user_auth"
