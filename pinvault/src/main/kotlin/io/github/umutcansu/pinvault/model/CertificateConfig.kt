package io.github.umutcansu.pinvault.model

/**
 * SSL certificate configuration fetched from the backend.
 * Contains everything needed to build a pinned OkHttpClient.
 *
 * Backend serves this as JSON:
 * ```json
 * {
 *   "version": 3,
 *   "pins": [
 *     {
 *       "hostname": "api.example.com",
 *       "sha256": ["AAAA...", "BBBB..."]
 *     }
 *   ],
 *   "forceUpdate": false
 * }
 * ```
 */
data class CertificateConfig(
    /** Global config version — computed as max of per-host versions. */
    val version: Int = 0,
    /** Pin configurations per hostname. */
    val pins: List<HostPin>,
    /** If true, client must update immediately regardless of schedule. */
    val forceUpdate: Boolean = false
) {
    /** Computed version from per-host versions (backward compat). */
    fun computedVersion(): Int = pins.maxOfOrNull { it.version } ?: version
}

/**
 * SHA-256 pin hashes for a specific hostname.
 * Must contain at least 2 pins (primary + backup) for safe rotation.
 *
 * For mTLS hosts, [mtls] is true and [clientCertVersion] tracks the client cert version.
 * The client downloads the host-specific P12 from the Config API when [clientCertVersion] changes.
 */
data class HostPin(
    /** Hostname pattern (e.g. "api.example.com" or "*.example.com"). */
    val hostname: String,
    /** SHA-256 hashes of the SubjectPublicKeyInfo (Base64-encoded). */
    val sha256: List<String>,
    /** Per-host version — incremented when this host's pins change. */
    val version: Int = 0,
    /** Per-host force update flag. */
    val forceUpdate: Boolean = false,
    /** Whether this host requires mutual TLS (client certificate). */
    val mtls: Boolean = false,
    /** Client cert version for this host. Null means no client cert available. */
    val clientCertVersion: Int? = null
) {
    init {
        require(sha256.size >= 2) {
            "At least 2 pins required (primary + backup) for hostname: $hostname"
        }
    }
}
