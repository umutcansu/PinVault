package io.github.umutcansu.pinvault.model

import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okio.ByteString.Companion.decodeBase64

/**
 * A single Config API endpoint registered on a [PinVaultConfig]. Each block
 * has its own TLS/mTLS pipeline, bootstrap pins, and vault endpoints.
 *
 * V2 introduces multi-Config-API support: a [PinVaultConfig] may hold one or
 * more blocks, and each [VaultFileConfig] binds to a specific block via
 * [VaultFileConfig.configApiId]. At runtime the library routes fetches to
 * the correct block's pin-verified OkHttpClient.
 *
 * Example:
 * ```kotlin
 * PinVaultConfig.Builder()
 *     .configApi("prod-tls", "https://host:8091") {
 *         bootstrapPins(listOf(HostPin("host:8091", listOf("…"))))
 *         wantPinsFor("cdn.example.com", "api.example.com")
 *     }
 *     .configApi("secure-mtls", "https://host:8092") {
 *         bootstrapPins(listOf(HostPin("host:8092", listOf("…"))))
 *         clientKeystore(p12Bytes, "changeit")
 *         wantPinsFor("internal.acme.com")
 *     }
 *     .vaultFile("feature-flags") { configApi("prod-tls"); ... }
 *     .vaultFile("ml-model") { configApi("secure-mtls"); storage(ENCRYPTED_FILE) }
 *     .build()
 * ```
 *
 * ## Removed in V2: `enrollmentToken(token)`
 * The builder used to accept a one-time enrollment token and store it on the
 * block. Nothing ever read it — neither
 * [io.github.umutcansu.pinvault.PinVault.enroll] nor
 * [io.github.umutcansu.pinvault.PinVault.autoEnroll] consulted the block — so
 * a token set here silently did nothing while looking like enrollment was
 * configured. Holding a single-use secret in a long-lived config object was
 * the wrong lifetime for it too.
 *
 * Pass the token at the call site instead:
 * ```kotlin
 * PinVault.enroll(context, token)   // token-based enrollment
 * PinVault.autoEnroll(context)      // deviceId-based enrollment
 * ```
 */
data class ConfigApiBlock @JvmOverloads constructor(
    /** Block identifier used by [VaultFileConfig.configApiId]. */
    val id: String,
    /** Base URL (trailing slash enforced on build). */
    val configUrl: String,
    /** Bootstrap pins compiled into the APK for initial connection. */
    val bootstrapPins: List<HostPin>,
    /** Relative path for certificate config endpoint. */
    val configEndpoint: String = PinVaultConfig.DEFAULT_CONFIG_ENDPOINT,
    /** Relative path for health check. */
    val healthEndpoint: String = PinVaultConfig.DEFAULT_HEALTH_ENDPOINT,
    /**
     * ECDSA P-256 signing key (Base64). Null = unsigned config accepted.
     * With several keys this is the first of [signaturePublicKeys].
     */
    val signaturePublicKey: String? = null,
    /** PKCS12 client keystore bytes for mTLS, bundled with the app. See [Builder.clientKeystore]. */
    val clientKeystoreBytes: ByteArray? = null,
    /**
     * Password of [clientKeystoreBytes], and of PKCS12 material kept in the
     * old form on a device whose Keystore refused the import. Default
     * "changeit" is a placeholder only.
     */
    val clientKeyPassword: String = "changeit",
    /** Enrollment endpoint path. */
    val enrollmentEndpoint: String = PinVaultConfig.DEFAULT_ENROLLMENT_ENDPOINT,
    /** Client cert download base path. */
    val clientCertEndpoint: String = PinVaultConfig.DEFAULT_CLIENT_CERT_ENDPOINT,
    /** Vault download report path. */
    val vaultReportEndpoint: String = PinVaultConfig.DEFAULT_VAULT_REPORT_ENDPOINT,
    /** Cert label for encrypted storage isolation. */
    val clientCertLabel: String = PinVaultConfig.DEFAULT_CERT_LABEL,
    /**
     * V2: pin scoping. When non-empty, the library sends `?hosts=…` to
     * [configEndpoint] so the server returns only pins for the intersection
     * of this list and the device's server-side ACL.
     *
     * Empty list = legacy behavior (trust server to return what it will).
     */
    val wantPinsFor: List<String> = emptyList(),
    /**
     * Every key a config signature may come from (Base64 X.509, ECDSA P-256).
     * Empty = just [signaturePublicKey]. See [Builder.signaturePublicKeys].
     */
    val signaturePublicKeys: List<String> = emptyList(),
    /** Distinct trusted keys that must sign each config. See [Builder.requiredSignatures]. */
    val requiredSignatures: Int = 1,
    /**
     * Offline keys that may authorise a new signing-key set (rotation and
     * revocation over the air). Empty = disabled. See [Builder.recoveryPublicKeys].
     */
    val recoveryPublicKeys: List<String> = emptyList(),
    /** Distinct recovery keys that must sign a key set. See [Builder.requiredRecoverySignatures]. */
    val requiredRecoverySignatures: Int = 1,
    /**
     * Where an expired (or refused) client certificate is renewed: a TLS
     * listener that asks for no client certificate. Null = [configUrl].
     * See [Builder.renewalUrl].
     */
    val renewalUrl: String? = null,
    /**
     * Where first enrollment goes: a TLS listener that asks for no client
     * certificate. Null = [configUrl]. See [Builder.enrollmentUrl].
     */
    val enrollmentUrl: String? = null,
    /** Renew when the remaining lifetime falls below this fraction. See [Builder.clientCertRenewalThreshold]. */
    val clientCertRenewalThreshold: Double = DEFAULT_RENEWAL_THRESHOLD,
    /** False = the library never renews on its own. See [Builder.disableClientCertRenewal]. */
    val clientCertRenewalEnabled: Boolean = true,
    /**
     * The server-side Config API id this block talks to. When set, a signed
     * config must name it (`configApiId` in the signed payload) or it is
     * refused. Null = not checked. See [Builder.serverScope].
     */
    val serverScope: String? = null,
    /**
     * True when the app called [Builder.allowUnsigned]. Only consulted for a
     * block that has signing keys AND a custom
     * [io.github.umutcansu.pinvault.api.CertificateConfigApi] that cannot
     * hand over signed envelopes: that combination is accepted only with it.
     */
    val allowUnsigned: Boolean = false,
    /**
     * True = the Config API may be reached without bootstrap pins or over
     * `http://`. See [Builder.allowUnpinnedConfigApi].
     */
    val allowUnpinnedConfigApi: Boolean = false,
    /**
     * True = a private key the server made may be this block's identity: a
     * PKCS12 answer to enrollment, and P12 enrollment when the device cannot
     * make its own key. See [Builder.allowServerGeneratedKey].
     */
    val allowServerGeneratedKey: Boolean = false,
    /**
     * SHA-256 pins (Base64) of the client CA's SubjectPublicKeyInfo. When not
     * empty, every issued client certificate must be signed by a chain
     * certificate that matches one. See [Builder.clientCaPins].
     */
    val clientCaPins: List<String> = emptyList(),
    /** Longest lifetime of a client certificate this block stores. See [Builder.maxClientCertLifetimeDays]. */
    val maxClientCertLifetimeDays: Int = DEFAULT_MAX_CLIENT_CERT_LIFETIME_DAYS,
    /**
     * Further listeners (`https://host:port/` or `host:port`) this block's
     * client identity is offered to, besides its own Config API, enrollment
     * and renewal URLs. See [Builder.clientCertHosts].
     */
    val clientCertHosts: List<String> = emptyList(),
    /** True = this block attests the device and carries a `PinVault-Token`. See [Builder.attestation]. */
    val attestationEnabled: Boolean = false,
    /**
     * How often the device re-attests at most, ms (the server's `nextAttestIn`
     * can ask for sooner). See [Builder.attestationInterval].
     */
    val attestationIntervalMs: Long = DEFAULT_ATTESTATION_INTERVAL_MS,
    /**
     * Hosts whose requests carry the token (pin host patterns, lower case).
     * Empty = every pinned host of this block's live config, plus its Config
     * API. See [Builder.tokenHosts].
     */
    val tokenHosts: List<String> = emptyList()
) {

    /**
     * Why this block must not be used, or null when it is fine: the Config
     * API (and the enrollment / renewal URLs) must be `https://` and the block
     * must carry bootstrap pins, unless [allowUnpinnedConfigApi] was asked
     * for. Checked at `PinVault.init` and by every client built for the
     * block, so a block made with the constructor instead of the builder is
     * held to the same rule.
     */
    internal fun configurationError(): String? {
        if (allowUnpinnedConfigApi) return null
        listOf("configUrl" to configUrl, "enrollmentUrl" to enrollmentUrl, "renewalUrl" to renewalUrl).forEach { (name, url) ->
            if (url != null && !url.trim().startsWith("https://", ignoreCase = true)) {
                return "Config API '$id': $name must be an https:// URL — a config fetched over plain HTTP can be " +
                    "replaced by anyone on the network. Call allowUnpinnedConfigApi() to accept that (tests, demos)."
            }
        }
        if (bootstrapPins.isEmpty()) {
            return "Config API '$id': bootstrapPins must not be empty — without them the first config fetch trusts " +
                "every certificate authority on the device. Call allowUnpinnedConfigApi() to accept that (tests, demos)."
        }
        return null
    }

    /**
     * The keys config signatures are checked against when no signing-key set
     * has been applied: [signaturePublicKeys], or [signaturePublicKey] alone
     * for blocks built through the primary constructor.
     */
    internal fun effectiveSignatureKeys(): List<String> =
        signaturePublicKeys.ifEmpty { listOfNotNull(signaturePublicKey) }

    class Builder(private val id: String, private val configUrl: String) {
        private var bootstrapPins: List<HostPin> = emptyList()
        private var configEndpoint: String = PinVaultConfig.DEFAULT_CONFIG_ENDPOINT
        private var healthEndpoint: String = PinVaultConfig.DEFAULT_HEALTH_ENDPOINT
        private var signaturePublicKeys: List<String> = emptyList()
        private var requiredSignatures: Int = 1
        private var recoveryPublicKeys: List<String> = emptyList()
        private var requiredRecoverySignatures: Int = 1
        private var allowUnsigned: Boolean = false
        private var clientKeystoreBytes: ByteArray? = null
        private var clientKeyPassword: String = "changeit"
        private var enrollmentEndpoint: String = PinVaultConfig.DEFAULT_ENROLLMENT_ENDPOINT
        private var clientCertEndpoint: String = PinVaultConfig.DEFAULT_CLIENT_CERT_ENDPOINT
        private var vaultReportEndpoint: String = PinVaultConfig.DEFAULT_VAULT_REPORT_ENDPOINT
        private var clientCertLabel: String = PinVaultConfig.DEFAULT_CERT_LABEL
        private var wantPinsFor: List<String> = emptyList()
        private var renewalUrl: String? = null
        private var enrollmentUrl: String? = null
        private var clientCertRenewalThreshold: Double = DEFAULT_RENEWAL_THRESHOLD
        private var clientCertRenewalEnabled: Boolean = true
        private var serverScope: String? = null
        private var allowUnpinnedConfigApi: Boolean = false
        private var allowServerGeneratedKey: Boolean = false
        private var clientCaPins: List<String> = emptyList()
        private var maxClientCertLifetimeDays: Int = DEFAULT_MAX_CLIENT_CERT_LIFETIME_DAYS
        private var clientCertHosts: List<String> = emptyList()
        private var attestationEnabled: Boolean = false
        private var attestationIntervalMs: Long = DEFAULT_ATTESTATION_INTERVAL_MS
        private var tokenHosts: List<String> = emptyList()

        fun bootstrapPins(pins: List<HostPin>) = apply { this.bootstrapPins = pins }
        fun configEndpoint(endpoint: String) = apply { this.configEndpoint = endpoint }
        fun healthEndpoint(endpoint: String) = apply { this.healthEndpoint = endpoint }
        /** The config-signing public key: X.509 SubjectPublicKeyInfo, Base64, ECDSA P-256. */
        fun signaturePublicKey(key: String) = apply {
            this.signaturePublicKeys = listOf(normalizeKeyText(key)).filter { it.isNotEmpty() }
        }

        /**
         * Several config-signing keys, any of which may sign (unless
         * [requiredSignatures] asks for more than one). Replaces an earlier
         * [signaturePublicKey] call.
         *
         * Typical use: the backend's key plus a backup whose private half is
         * kept offline. If the primary is lost or stolen, the backend starts
         * signing with the backup and every installed app keeps accepting
         * configs — no app update. A stolen primary stays trusted, though,
         * until the app is updated or [recoveryPublicKeys] revokes it.
         */
        fun signaturePublicKeys(vararg keys: String) = apply {
            this.signaturePublicKeys = keys.map(::normalizeKeyText).filter { it.isNotEmpty() }.distinct()
        }

        /** [signaturePublicKeys] for a list (Java-friendly). */
        fun signaturePublicKeys(keys: List<String>) = signaturePublicKeys(*keys.toTypedArray())

        /**
         * How many DISTINCT keys from [signaturePublicKeys] must sign every
         * config (and every vault file of this block). Default 1.
         *
         * With 2 or more, and the keys held by different people or systems,
         * nobody — not a single administrator, not the config server itself —
         * can publish pins alone. The backend then sends all signatures in the
         * envelope's `signatures` field.
         */
        fun requiredSignatures(count: Int) = apply { this.requiredSignatures = count }

        /**
         * Offline recovery keys that may authorise a new set of signing keys.
         * Enables signing-key rotation and revocation without an app update:
         * the backend delivers a key set signed by these keys, and the device
         * from then on trusts exactly the signing keys that set lists.
         *
         * Recovery keys are only ever used for that — never to sign configs —
         * and must not also appear in [signaturePublicKeys]. Keep their private
         * halves offline and apart from the signing keys.
         */
        fun recoveryPublicKeys(vararg keys: String) = apply {
            this.recoveryPublicKeys = keys.map(::normalizeKeyText).filter { it.isNotEmpty() }.distinct()
        }

        /** [recoveryPublicKeys] for a list (Java-friendly). */
        fun recoveryPublicKeys(keys: List<String>) = recoveryPublicKeys(*keys.toTypedArray())

        /** How many distinct [recoveryPublicKeys] must sign a key set. Default 1. */
        fun requiredRecoverySignatures(count: Int) = apply { this.requiredRecoverySignatures = count }

        /**
         * Explicit opt-out from signed-config enforcement. Without this call,
         * [build] requires [signaturePublicKey] to be set — protects against
         * the common footgun of forgetting it in production, which would
         * disable signature *and* replay/freshness protection.
         *
         * SECURITY (audit L-8): unsigned mode does more than skip the
         * signature. It also disables ALL of the freshness machinery —
         * `issuedAt` / `expiresAt` stay `0`, so there is NO replay protection,
         * NO config-expiry window, and NO `issuedAt`-based downgrade rejection.
         * A MITM in front of an unsigned config endpoint can therefore serve
         * arbitrary or rolled-back pins. Use ONLY in tests, throwaway demos, or
         * transitional setups where the backend has no ECDSA signing key yet,
         * and document the risk wherever it is called.
         *
         * The stored config of an unsigned block has no integrity check either:
         * a signed block keeps the signed envelope and verifies it again every
         * time the stored config is read; an unsigned one has nothing to verify.
         *
         * Together with signing keys this call has one more meaning. A block
         * with keys and a custom `CertificateConfigApi` gets verified configs
         * only when that API implements
         * [io.github.umutcansu.pinvault.api.SignedConfigSource]; when it does
         * not, `PinVault.init` fails — unless this was called, which accepts
         * the custom API's configs unverified (the keys then only check vault
         * files). With the library's own HTTP client a block that has keys is
         * always verified, whatever this says.
         */
        fun allowUnsigned() = apply { this.allowUnsigned = true }

        /**
         * The id of the Config API on the server this block talks to (the
         * reference server's Config API id, e.g. `default-tls`).
         *
         * One signing key often signs for several Config APIs. Without this,
         * a config signed for another of them — other hosts, other pins — is
         * accepted here, because its signature is valid. With it, the signed
         * payload must carry `"configApiId": "<id>"` with exactly this value;
         * a payload without the field, or with another id, is refused. Needs
         * a server that writes the field (the reference server does).
         *
         * Not set: the field is ignored, as before. It has no effect on an
         * unsigned block — there is no signature to bind it to.
         */
        fun serverScope(id: String) = apply {
            require(id.isNotBlank()) { "serverScope must not be blank" }
            this.serverScope = id.trim()
        }

        /**
         * Explicit opt-out from the two rules every Config API block is held
         * to at `PinVault.init`: an `https://` URL (also for `enrollmentUrl`
         * and `renewalUrl`) and at least one bootstrap pin.
         *
         * SECURITY: without bootstrap pins the first config fetch trusts
         * every certificate authority on the device; over `http://` anyone on
         * the network path reads and — for an unsigned block — rewrites the
         * config. Tests against a local plain-HTTP server and throwaway demos
         * only.
         */
        fun allowUnpinnedConfigApi() = apply { this.allowUnpinnedConfigApi = true }

        /**
         * mTLS client keystore bundled with the app. Default password
         * "changeit" is placeholder only.
         *
         * The private key is imported into the Android Keystore as a
         * non-exportable key when the block is first used and presented from
         * there. The bytes passed here stay in the app (and in the APK they
         * were read from), so a bundled key is the same for every install and
         * readable by anyone who unpacks the app: use it to reach an mTLS
         * Config API before enrollment, not as a device identity.
         */
        fun clientKeystore(bytes: ByteArray, password: String = "changeit") = apply {
            this.clientKeystoreBytes = bytes
            this.clientKeyPassword = password
        }

        /**
         * Accept a private key the SERVER generated as this block's identity.
         *
         * By default the device makes its own key in the Android Keystore
         * and enrolls with a certificate signing request; the key never
         * exists anywhere else. Without this call the library refuses
         *  - a PKCS12 answer to an enrollment (an older or P12-only server), and
         *  - enrolling without a CSR when the Keystore cannot make a key:
         * `enrollForResult` then returns `Failed` and says so. (The reference
         * server answers such a request `403 csr_required` unless its
         * `ENROLLMENT_P12` is on.)
         *
         * With it, both are accepted. A key that came in a P12 has been on
         * the server and on the wire; the library imports it into the Android
         * Keystore as a non-exportable key and keeps only the certificate
         * chain, but it cannot undo that. Such an identity is not renewed.
         */
        fun allowServerGeneratedKey() = apply { this.allowServerGeneratedKey = true }

        /**
         * Pins the client CA: the certificate authority that issues this
         * block's client certificates. Each value is the Base64 SHA-256 of a
         * CA certificate's SubjectPublicKeyInfo — the same form as a host pin
         * (a leading `sha256/` is accepted).
         *
         * With pins, a certificate chain the server issues — at enrollment
         * and at every renewal — is stored only when it has at least two
         * certificates, the leaf is over this device's key, valid now, and
         * signed by a certificate of the chain whose key matches a pin.
         * Without them the first chain is trusted as it comes from the pinned
         * enrollment listener, and a renewal must be signed by the CA of the
         * certificate it replaces. Pin the current CA and its successor to
         * rotate the CA without an app update.
         */
        fun clientCaPins(vararg spkiSha256Base64: String) = apply {
            this.clientCaPins = spkiSha256Base64.map { pin ->
                val value = pin.trim().removePrefix("sha256/")
                // Okio, not android.util.Base64: builders also run in plain JVM tests.
                val decoded = value.decodeBase64()
                require(decoded != null && decoded.size == 32) {
                    "clientCaPins: '$pin' is not a Base64 SHA-256 hash (44 characters)"
                }
                decoded.base64()
            }.distinct()
        }

        /** [clientCaPins] for a list (Java-friendly). */
        fun clientCaPins(pins: List<String>) = clientCaPins(*pins.toTypedArray())

        /**
         * The longest lifetime (`notAfter - notBefore`, and `notAfter` from
         * now) of a client certificate this block stores. Default 825 days.
         * A chain with a longer-lived leaf is refused at enrollment and at
         * renewal, and a stored one is renewed at the next check: a
         * certificate that never comes up for renewal is never looked at
         * again by the server.
         */
        fun maxClientCertLifetimeDays(days: Int) = apply {
            require(days >= 1) { "maxClientCertLifetimeDays must be at least 1" }
            this.maxClientCertLifetimeDays = days
        }
        /**
         * Further listeners this block's client identity may be presented to,
         * as `https://host:port/` or `host:port` (the port is required). The
         * identity always goes to the block's own Config API, enrollment and
         * renewal URLs; any other host that asks for a client certificate gets
         * none, because the certificate names the device. List here an mTLS
         * API the app calls with this block's client (for example a second
         * listener of the same backend).
         *
         * Compiled in, and once set it is the whole list: the server config
         * cannot add hosts to it — a pin entry with `mtls = true` then gets
         * the identity only if its host is listed here (or is one of the
         * block's own URLs). A block that sets no `clientCertHosts` keeps the
         * earlier behaviour, where the signed config's `mtls = true` entries
         * name the hosts the identity goes to (so whoever signs the config
         * can name them). Host-specific client certificates are unaffected.
         */
        fun clientCertHosts(vararg hosts: String) = apply {
            this.clientCertHosts = hosts.map { h ->
                val url = if (h.contains("://")) h.trim() else "https://${h.trim()}/"
                val parsed = url.toHttpUrlOrNull()
                require(parsed != null && parsed.isHttps && Regex(":\\d+").containsMatchIn(url.substringAfter("://").substringBefore("/"))) {
                    "clientCertHosts: '$h' must be https://host:port/ or host:port"
                }
                url
            }.distinct()
        }

        /** [clientCertHosts] for a list (Java-friendly). */
        fun clientCertHosts(hosts: List<String>) = clientCertHosts(*hosts.toTypedArray())

        fun enrollmentEndpoint(endpoint: String) = apply { this.enrollmentEndpoint = endpoint }
        fun clientCertEndpoint(endpoint: String) = apply { this.clientCertEndpoint = endpoint }
        fun vaultReportEndpoint(endpoint: String) = apply { this.vaultReportEndpoint = endpoint }
        fun clientCertLabel(label: String) = apply { this.clientCertLabel = label }

        /**
         * V2: declare which hostnames this device wants pins for. Server
         * filters its response to the intersection of this set and the
         * device's ACL. Least-privilege: cihaz istediği pin'leri açıkça
         * söylesin, hepsine erişemesin.
         */
        fun wantPinsFor(vararg hosts: String) = apply { this.wantPinsFor = hosts.toList() }

        /**
         * Where the device renews a client certificate that has already
         * expired (or that the server refused). An mTLS Config API cannot be
         * reached without a valid certificate, so this must be a plain-TLS
         * listener of the same backend — the device proves its identity there
         * by signing the CSR with its Keystore key, not with a certificate.
         *
         * Default: the block's own URL, which is right for a TLS Config API.
         * The host must be covered by [bootstrapPins]; pinning its issuer
         * (the backend's own CA) rather than its leaf keeps this door open
         * across the backend's own certificate renewals.
         */
        fun renewalUrl(url: String) = apply {
            require(url.isNotBlank()) { "renewalUrl must not be blank" }
            this.renewalUrl = if (url.endsWith("/")) url else "$url/"
        }

        /**
         * Where `PinVault.enroll` / `autoEnroll` send the first enrollment. A
         * device has no client certificate before it enrolls, so an mTLS
         * Config API refuses it at the handshake; point this at the backend's
         * plain-TLS listener instead. The host must be covered by
         * [bootstrapPins]. Default: the block's own URL, right for a TLS
         * Config API.
         */
        fun enrollmentUrl(url: String) = apply {
            require(url.isNotBlank()) { "enrollmentUrl must not be blank" }
            this.enrollmentUrl = if (url.endsWith("/")) url else "$url/"
        }

        /**
         * Renew the client certificate once its remaining lifetime drops
         * below this fraction of the whole lifetime. Default 1/3: a 90-day
         * certificate is renewed with 30 days to spare, while it is still
         * valid and can be renewed over the normal mTLS connection.
         */
        fun clientCertRenewalThreshold(fraction: Double) = apply {
            require(fraction > 0.0 && fraction < 1.0) { "clientCertRenewalThreshold must be between 0 and 1 (exclusive)" }
            this.clientCertRenewalThreshold = fraction
        }

        /**
         * Turns automatic renewal off for this block. `PinVault.renewClientCertIfNeeded(force = true)`
         * still works, so the host app can drive renewal on its own schedule.
         */
        fun disableClientCertRenewal() = apply { this.clientCertRenewalEnabled = false }

        /**
         * Attest this device with the block's server (`ATTESTATION.md`): at
         * init and every few minutes the library measures the app and the
         * device, signs the report with the block's device key and sends it
         * to `POST api/v1/attest`; on a pass the server issues a short-lived
         * `PinVault-Token`, which every client the library builds or
         * configures adds to requests for the [tokenHosts], and may embed a
         * fresh signed pin config. On a reject there is no token and no
         * config through this channel — `init` still succeeds; the app reads
         * `PinVault.attestationStatus()`.
         *
         * Off by default. Needs the library's own HTTP client: a block with a
         * custom `CertificateConfigApi` reports `UNSUPPORTED`.
         */
        fun attestation() = apply { this.attestationEnabled = true }

        /**
         * How often the device re-attests at most. Default 5 minutes, at
         * least 1 minute. The server's `nextAttestIn` and the token's expiry
         * can make it sooner (the library re-attests at
         * `min(nextAttestIn, this, tokenExpiry − 60 s)` with ±10 % jitter), never later.
         */
        fun attestationInterval(amount: Long, unit: java.util.concurrent.TimeUnit) = apply {
            val ms = unit.toMillis(amount)
            require(ms >= MIN_ATTESTATION_INTERVAL_MS) { "attestationInterval must be at least 1 minute" }
            this.attestationIntervalMs = ms
        }

        /**
         * Which hosts' requests carry the `PinVault-Token`: pin host patterns
         * (`api.example.com`, `*.cdn.example.com`, optionally `:port`), the
         * same syntax as a pin entry. Not set: every host pinned by this
         * block's live config, and the block's own Config API.
         */
        fun tokenHosts(vararg patterns: String) = apply {
            this.tokenHosts = patterns.map { pattern ->
                val host = pattern.trim().lowercase()
                io.github.umutcansu.pinvault.ssl.PinConfigValidator.hostPatternError(host)?.let {
                    throw IllegalArgumentException("tokenHosts: $it")
                }
                host
            }.distinct()
        }

        /** [tokenHosts] for a list (Java-friendly). */
        fun tokenHosts(patterns: List<String>) = tokenHosts(*patterns.toTypedArray())

        internal fun build(): ConfigApiBlock {
            require(id.isNotBlank()) { "ConfigApi id must not be blank" }
            require(configUrl.isNotBlank()) { "ConfigApi configUrl must not be blank" }
            require(signaturePublicKeys.isNotEmpty() || allowUnsigned) {
                "ConfigApi '$id': signaturePublicKey is required. Pass the ECDSA P-256 " +
                "public key (X.509-encoded, Base64) via signaturePublicKey(...) — this " +
                "is what guards against config tampering and replay attacks. If you are " +
                "intentionally running without signed configs (tests, demos, transitional " +
                "setup), call allowUnsigned() to opt out explicitly."
            }
            if (signaturePublicKeys.isNotEmpty()) {
                require(requiredSignatures in 1..signaturePublicKeys.size) {
                    "ConfigApi '$id': requiredSignatures($requiredSignatures) must be between 1 and " +
                    "the number of signing keys (${signaturePublicKeys.size})."
                }
            }
            if (recoveryPublicKeys.isNotEmpty()) {
                require(signaturePublicKeys.isNotEmpty()) {
                    "ConfigApi '$id': recoveryPublicKeys(...) rotates signing keys, so it needs " +
                    "signaturePublicKey(...) / signaturePublicKeys(...) as the starting set."
                }
                require(recoveryPublicKeys.none { it in signaturePublicKeys }) {
                    "ConfigApi '$id': a recovery key must not also be a signing key — keep the two " +
                    "roles on separate keys."
                }
                require(requiredRecoverySignatures in 1..recoveryPublicKeys.size) {
                    "ConfigApi '$id': requiredRecoverySignatures($requiredRecoverySignatures) must be " +
                    "between 1 and the number of recovery keys (${recoveryPublicKeys.size})."
                }
            }
            val normalizedUrl = if (configUrl.endsWith("/")) configUrl else "$configUrl/"
            return ConfigApiBlock(
                id = id,
                configUrl = normalizedUrl,
                bootstrapPins = bootstrapPins,
                configEndpoint = configEndpoint.trimStart('/'),
                healthEndpoint = healthEndpoint.trimStart('/'),
                // The first key keeps the single-key field meaningful for code
                // written before multi-key support.
                signaturePublicKey = signaturePublicKeys.firstOrNull(),
                clientKeystoreBytes = clientKeystoreBytes,
                clientKeyPassword = clientKeyPassword,
                enrollmentEndpoint = enrollmentEndpoint,
                clientCertEndpoint = clientCertEndpoint.trimStart('/'),
                vaultReportEndpoint = vaultReportEndpoint.trimStart('/'),
                clientCertLabel = clientCertLabel,
                wantPinsFor = wantPinsFor,
                signaturePublicKeys = signaturePublicKeys,
                requiredSignatures = requiredSignatures,
                recoveryPublicKeys = recoveryPublicKeys,
                requiredRecoverySignatures = requiredRecoverySignatures,
                renewalUrl = renewalUrl,
                enrollmentUrl = enrollmentUrl,
                clientCertRenewalThreshold = clientCertRenewalThreshold,
                clientCertRenewalEnabled = clientCertRenewalEnabled,
                serverScope = serverScope,
                allowUnsigned = allowUnsigned,
                allowUnpinnedConfigApi = allowUnpinnedConfigApi,
                allowServerGeneratedKey = allowServerGeneratedKey,
                clientCaPins = clientCaPins,
                maxClientCertLifetimeDays = maxClientCertLifetimeDays,
                clientCertHosts = clientCertHosts,
                attestationEnabled = attestationEnabled,
                attestationIntervalMs = attestationIntervalMs,
                tokenHosts = tokenHosts
            )
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is ConfigApiBlock) return false
        return id == other.id && configUrl == other.configUrl &&
                bootstrapPins == other.bootstrapPins &&
                configEndpoint == other.configEndpoint &&
                healthEndpoint == other.healthEndpoint &&
                signaturePublicKey == other.signaturePublicKey &&
                (clientKeystoreBytes?.contentEquals(other.clientKeystoreBytes) ?: (other.clientKeystoreBytes == null)) &&
                clientKeyPassword == other.clientKeyPassword &&
                enrollmentEndpoint == other.enrollmentEndpoint &&
                clientCertEndpoint == other.clientCertEndpoint &&
                vaultReportEndpoint == other.vaultReportEndpoint &&
                clientCertLabel == other.clientCertLabel &&
                wantPinsFor == other.wantPinsFor &&
                signaturePublicKeys == other.signaturePublicKeys &&
                requiredSignatures == other.requiredSignatures &&
                recoveryPublicKeys == other.recoveryPublicKeys &&
                requiredRecoverySignatures == other.requiredRecoverySignatures &&
                renewalUrl == other.renewalUrl &&
                enrollmentUrl == other.enrollmentUrl &&
                clientCertRenewalThreshold == other.clientCertRenewalThreshold &&
                clientCertRenewalEnabled == other.clientCertRenewalEnabled &&
                serverScope == other.serverScope &&
                allowUnsigned == other.allowUnsigned &&
                allowUnpinnedConfigApi == other.allowUnpinnedConfigApi &&
                allowServerGeneratedKey == other.allowServerGeneratedKey &&
                clientCaPins == other.clientCaPins &&
                maxClientCertLifetimeDays == other.maxClientCertLifetimeDays &&
                clientCertHosts == other.clientCertHosts &&
                attestationEnabled == other.attestationEnabled &&
                attestationIntervalMs == other.attestationIntervalMs &&
                tokenHosts == other.tokenHosts
    }

    override fun hashCode(): Int {
        var r = id.hashCode()
        r = 31 * r + configUrl.hashCode()
        r = 31 * r + bootstrapPins.hashCode()
        r = 31 * r + configEndpoint.hashCode()
        r = 31 * r + healthEndpoint.hashCode()
        r = 31 * r + (signaturePublicKey?.hashCode() ?: 0)
        r = 31 * r + (clientKeystoreBytes?.contentHashCode() ?: 0)
        r = 31 * r + clientKeyPassword.hashCode()
        r = 31 * r + enrollmentEndpoint.hashCode()
        r = 31 * r + clientCertEndpoint.hashCode()
        r = 31 * r + vaultReportEndpoint.hashCode()
        r = 31 * r + clientCertLabel.hashCode()
        r = 31 * r + wantPinsFor.hashCode()
        r = 31 * r + signaturePublicKeys.hashCode()
        r = 31 * r + requiredSignatures
        r = 31 * r + recoveryPublicKeys.hashCode()
        r = 31 * r + requiredRecoverySignatures
        r = 31 * r + (renewalUrl?.hashCode() ?: 0)
        r = 31 * r + (enrollmentUrl?.hashCode() ?: 0)
        r = 31 * r + clientCertRenewalThreshold.hashCode()
        r = 31 * r + clientCertRenewalEnabled.hashCode()
        r = 31 * r + (serverScope?.hashCode() ?: 0)
        r = 31 * r + allowUnsigned.hashCode()
        r = 31 * r + allowUnpinnedConfigApi.hashCode()
        r = 31 * r + allowServerGeneratedKey.hashCode()
        r = 31 * r + clientCaPins.hashCode()
        r = 31 * r + maxClientCertLifetimeDays
        r = 31 * r + clientCertHosts.hashCode()
        r = 31 * r + attestationEnabled.hashCode()
        r = 31 * r + attestationIntervalMs.hashCode()
        r = 31 * r + tokenHosts.hashCode()
        return r
    }

    companion object {
        const val DEFAULT_ID = "default"

        /** Re-attest every 5 minutes unless the server or the token say sooner. */
        const val DEFAULT_ATTESTATION_INTERVAL_MS: Long = 5L * 60 * 1000

        /** Shortest [Builder.attestationInterval]. */
        const val MIN_ATTESTATION_INTERVAL_MS: Long = 60L * 1000

        /** Renew with a third of the lifetime left. */
        const val DEFAULT_RENEWAL_THRESHOLD: Double = 1.0 / 3

        /** Longest client-certificate lifetime accepted unless the block says otherwise (days). */
        const val DEFAULT_MAX_CLIENT_CERT_LIFETIME_DAYS: Int = 825

        /**
         * Strips PEM armour and whitespace so a key pasted as a PEM block, or
         * with a trailing newline from a properties file, is one key and not
         * two. The runtime additionally parses every key and compares the
         * parsed form (see SignatureTrust), which this pure-text step cannot.
         */
        internal fun normalizeKeyText(key: String): String =
            key.lineSequence()
                .map { it.trim() }
                .filter { it.isNotEmpty() && !it.startsWith("-----") }
                .joinToString("")
                .filterNot { it.isWhitespace() }
    }
}
