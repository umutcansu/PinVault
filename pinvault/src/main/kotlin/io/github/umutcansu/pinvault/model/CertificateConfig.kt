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
    /** Config version — incremented on every backend update. */
    val version: Int,
    /** Pin configurations per hostname. */
    val pins: List<HostPin>,
    /** If true, client must update immediately regardless of schedule. */
    val forceUpdate: Boolean = false
)

/**
 * SHA-256 pin hashes for a specific hostname.
 * Must contain at least 2 pins (primary + backup) for safe rotation.
 */
data class HostPin(
    /** Hostname pattern (e.g. "api.example.com" or "*.example.com"). */
    val hostname: String,
    /** SHA-256 hashes of the SubjectPublicKeyInfo (Base64-encoded). */
    val sha256: List<String>
) {
    init {
        require(sha256.size >= 2) {
            "At least 2 pins required (primary + backup) for hostname: $hostname"
        }
    }
}
