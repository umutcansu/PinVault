package io.github.umutcansu.pinvault.ssl

import io.github.umutcansu.pinvault.model.CertificateConfig
import io.github.umutcansu.pinvault.model.HostPin
import io.github.umutcansu.pinvault.model.InvalidPinFormatException

/**
 * What a pin config may contain, checked before anything else looks at it:
 * at intake (a fetched config, static pins) and again when a stored config is
 * read back.
 *
 * Host names used to be taken as they came. A name carrying the old store's
 * separators (`api.bank.com|9|<pin>,<pin>|false\nx`) was written to disk as
 * one entry and read back as another, and a name like `*.com` pinned a whole
 * top-level domain. A config with one bad entry is refused as a whole: a
 * partly applied config is not what its signer signed.
 */
internal object PinConfigValidator {

    /** Longest accepted host pattern, the `*.` prefix included and the port excluded. */
    const val MAX_HOSTNAME_LENGTH = 253

    /** Most pin entries a config may carry. */
    const val MAX_HOSTS = 2000

    /** Most pins one host may carry. */
    const val MAX_PINS_PER_HOST = 32

    /** Most managed trust roots a config may list. */
    const val MAX_TRUST_ROOTS = 64

    private val LABEL = Regex("[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")
    private val PORT = Regex("[1-9][0-9]{0,4}")

    /** Base64 of 32 bytes: 43 characters and one `=`. */
    private val PIN = Regex("[A-Za-z0-9+/]{43}=")

    /**
     * Suffixes under which names are handed out to unrelated parties, so a
     * wildcard directly under one would cover hosts of different owners. A
     * short list of the common ones, not the whole Public Suffix List — the
     * rule every wildcard must pass is "at least two labels after `*.`", this
     * list only catches the well-known two-label registries on top of that.
     */
    private val MULTI_LABEL_PUBLIC_SUFFIXES = setOf(
        "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk",
        "com.au", "net.au", "org.au", "edu.au", "gov.au",
        "co.nz", "org.nz", "net.nz",
        "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp",
        "com.tr", "org.tr", "net.tr", "gov.tr", "edu.tr", "gen.tr", "web.tr",
        "com.br", "net.br", "org.br", "gov.br",
        "com.cn", "net.cn", "org.cn", "gov.cn",
        "co.in", "net.in", "org.in", "gov.in",
        "co.za", "org.za", "co.kr", "or.kr", "co.il", "org.il", "co.id", "co.th",
        "com.mx", "com.ar", "com.co", "com.sg", "com.hk", "com.tw", "com.my", "com.ph",
        "com.sa", "com.eg", "com.ua", "com.pl", "com.ru", "com.de",
        "github.io", "gitlab.io", "herokuapp.com", "appspot.com", "web.app", "firebaseapp.com",
        "azurewebsites.net", "cloudfront.net", "netlify.app", "vercel.app", "pages.dev", "workers.dev"
    )

    /**
     * [config] with the optional lists Gson left null (absent from the JSON)
     * set to empty, so code past intake can trust their Kotlin types.
     */
    fun normalized(config: CertificateConfig): CertificateConfig {
        @Suppress("USELESS_CAST")
        return if ((config.trustRoots as List<String>?) == null) config.copy(trustRoots = emptyList()) else config
    }

    /**
     * Throws [InvalidPinFormatException] unless [config] has at least one pin
     * entry and every entry is well-formed: a valid host pattern, no host
     * named twice, a version that is not negative, and at least two pins that
     * are each the Base64 of a SHA-256.
     *
     * Gson fills absent fields with null whatever their Kotlin type says, so
     * every field is read as nullable here.
     */
    fun validate(config: CertificateConfig) {
        @Suppress("USELESS_CAST")
        val pins = (config.pins as List<HostPin?>?)
            ?: throw InvalidPinFormatException("Config must contain at least one pin entry")
        if (pins.isEmpty()) throw InvalidPinFormatException("Config must contain at least one pin entry")
        if (pins.size > MAX_HOSTS) throw InvalidPinFormatException("Config has ${pins.size} pin entries (at most $MAX_HOSTS)")

        @Suppress("USELESS_CAST")
        val roots = (config.trustRoots as List<String?>?).orEmpty()
        if (roots.size > MAX_TRUST_ROOTS) throw InvalidPinFormatException("Config lists ${roots.size} trust roots (at most $MAX_TRUST_ROOTS)")
        roots.forEachIndexed { index, root ->
            pinError(root)?.let { throw InvalidPinFormatException("Trust root at index $index $it") }
        }
        if (roots.toSet().size != roots.size) throw InvalidPinFormatException("A trust root is listed more than once")

        val seen = HashSet<String>()
        pins.forEach { pin ->
            if (pin == null) throw InvalidPinFormatException("Config has an empty pin entry")
            @Suppress("USELESS_CAST")
            val hostname = pin.hostname as String?
            hostPatternError(hostname)?.let { throw InvalidPinFormatException(it) }
            if (!seen.add(hostname!!.lowercase())) {
                throw InvalidPinFormatException("Host ${printable(hostname)} is listed more than once")
            }
            if (pin.version < 0) {
                throw InvalidPinFormatException("Host ${printable(hostname)} has a negative version (${pin.version})")
            }
            @Suppress("USELESS_CAST")
            val hashes = (pin.sha256 as List<String?>?).orEmpty()
            if (hashes.size < 2) {
                throw InvalidPinFormatException("Host ${printable(hostname)} must have at least 2 pins (primary + backup)")
            }
            if (hashes.size > MAX_PINS_PER_HOST) {
                throw InvalidPinFormatException("Host ${printable(hostname)} has ${hashes.size} pins (at most $MAX_PINS_PER_HOST)")
            }
            // Two pins exist so that one key can be rotated away while the
            // other still works; the same hash twice gives that rotation
            // nothing to fall back on and used to satisfy the count.
            if (hashes.toSet().size < 2) {
                throw InvalidPinFormatException(
                    "Host ${printable(hostname)} must have at least 2 different pins (primary + backup); the same pin is listed twice"
                )
            }
            hashes.forEachIndexed { index, hash ->
                pinError(hash)?.let { throw InvalidPinFormatException("Hash at index $index for ${printable(hostname)} $it") }
            }
        }
    }

    /**
     * Null when [pattern] is a host a pin entry may name, else the reason it
     * is not. Accepted: letter-digit-hyphen labels joined by dots (an IPv4
     * address is that too), optionally one leading `*.` that stands for
     * exactly one label, optionally `:port` (1–65535). At most
     * [MAX_HOSTNAME_LENGTH] characters without the port. A wildcard needs at
     * least two labels after it and must not sit directly under a public
     * suffix (`*.com`, `*.co.uk`). IPv6 literals are not accepted.
     */
    fun hostPatternError(pattern: String?): String? {
        if (pattern.isNullOrEmpty()) return "A pin entry has no hostname"
        val shown = printable(pattern)
        val colon = pattern.lastIndexOf(':')
        val host = if (colon >= 0) pattern.substring(0, colon) else pattern
        if (colon >= 0) {
            val port = pattern.substring(colon + 1)
            if (!PORT.matches(port) || port.toInt() > 65535) {
                return "Hostname $shown has an invalid port (1–65535, digits only)"
            }
        }
        if (host.isEmpty() || host.length > MAX_HOSTNAME_LENGTH) {
            return "Hostname $shown must be 1–$MAX_HOSTNAME_LENGTH characters long"
        }
        val wildcard = host.startsWith("*.")
        val labels = (if (wildcard) host.substring(2) else host).split('.')
        if (labels.any { !LABEL.matches(it) }) {
            return "Hostname $shown is not a host name: labels are letters, digits and hyphens, joined by dots, " +
                "with at most one leading '*.'"
        }
        if (wildcard) {
            val suffix = labels.joinToString(".").lowercase()
            if (labels.size < 2 || labels.last().all { it.isDigit() } || suffix in MULTI_LABEL_PUBLIC_SUFFIXES) {
                return "Hostname $shown is a wildcard over a public suffix or an address; a wildcard needs a " +
                    "registered domain after '*.' (e.g. *.example.com)"
            }
        }
        return null
    }

    /** Null when [hash] is the Base64 of a SHA-256 (44 characters), else what is wrong with it. */
    fun pinError(hash: String?): String? = when {
        hash.isNullOrBlank() -> "is blank"
        hash.length != 44 -> "has invalid length: ${hash.length} (expected 44)"
        !PIN.matches(hash) -> "is not valid Base64 of a SHA-256"
        else -> null
    }

    /** [value] made safe for a log line or an error message: no control characters, bounded. */
    private fun printable(value: String): String =
        "'" + value.take(80).map { if (it.isISOControl()) '?' else it }.joinToString("") +
            (if (value.length > 80) "…" else "") + "'"
}
