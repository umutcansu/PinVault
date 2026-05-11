package io.github.umutcansu.pinvault.ssl

/**
 * Hostname → pin-set resolution for the pinning trust manager. Lives at the
 * package level (rather than inside [DynamicSSLManager]) so it can be tested
 * in isolation — the trust manager itself is constructed inside a closure
 * and isn't easily reachable from a test.
 *
 * Security boundary (H-01): a cert pinned for host A must NOT validate for
 * host B even when both come from the same PinVaultConfig. Pre-V2 the
 * library flattened every host's hashes into one set, so a leak of any one
 * host's private key let an attacker MITM every other pinned host in the
 * config. Per-host scoping closes that path.
 */
internal object PinHostMatcher {

    /**
     * Builds a per-host map of accepted SHA-256 pin hashes from a list of
     * `(hostname, hashes)` pairs. Hostnames are lowercased to make lookup
     * case-insensitive. Wildcard patterns like `*.example.com` are kept
     * verbatim — they are resolved at lookup time by [match].
     */
    fun build(entries: List<Pair<String, Set<String>>>): Map<String, Set<String>> =
        entries.associate { (host, hashes) -> host.lowercase() to hashes }

    /**
     * Looks up the accepted pin set for [hostname]:
     *   1. Exact (case-insensitive) hostname match.
     *   2. Wildcard match — any pin entry whose hostname starts with `*.`
     *      matches a single sub-label of the queried hostname. For example,
     *      `*.example.com` matches `api.example.com` but NOT `example.com`
     *      (zero labels left) or `a.b.example.com` (two labels left).
     *
     * Returns `null` when nothing matches — callers must treat null as a
     * hard reject (fail-safe).
     */
    fun match(pinMap: Map<String, Set<String>>, hostname: String): Set<String>? {
        val host = hostname.lowercase()
        pinMap[host]?.let { return it }

        for ((pattern, hashes) in pinMap) {
            if (!pattern.startsWith("*.")) continue
            val suffix = pattern.substring(2)
            if (!host.endsWith(".$suffix")) continue
            val left = host.substring(0, host.length - suffix.length - 1)
            if (left.isNotEmpty() && '.' !in left) return hashes
        }
        return null
    }
}
