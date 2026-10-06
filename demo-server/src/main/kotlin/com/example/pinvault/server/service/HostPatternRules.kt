package com.example.pinvault.server.service

/**
 * The host-name rules of a pin entry, the same as the Android library's
 * (`ssl/PinConfigValidator.hostPatternError`): LDH labels joined by dots, at
 * most one leading `*.`, an optional `:port` (1–65535), at most 253
 * characters, and no wildcard over a public suffix or an address (`*.com`,
 * `*.co.uk`, `*.1`). The library refuses a whole config that breaks them,
 * so the server refuses such an entry when it is written instead of
 * publishing a config every device would reject.
 */
object HostPatternRules {

    private const val MAX_HOSTNAME_LENGTH = 253
    private val LABEL = Regex("[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")
    private val PORT = Regex("[1-9][0-9]{0,4}")

    /** Keep in step with the library's list. */
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

    /** Why [pattern] is not a valid pin host entry, or null when it is. */
    fun error(pattern: String?): String? {
        if (pattern.isNullOrEmpty()) return "Hostname bos olamaz"
        val shown = "'" + pattern.take(80).map { if (it.isISOControl()) '?' else it }.joinToString("") + "'"
        val colon = pattern.lastIndexOf(':')
        val host = if (colon >= 0) pattern.substring(0, colon) else pattern
        if (colon >= 0) {
            val port = pattern.substring(colon + 1)
            if (!PORT.matches(port) || port.toInt() > 65535) return "$shown: gecersiz port (1–65535)"
        }
        if (host.isEmpty() || host.length > MAX_HOSTNAME_LENGTH) return "$shown: 1–$MAX_HOSTNAME_LENGTH karakter olmali"
        val wildcard = host.startsWith("*.")
        val labels = (if (wildcard) host.substring(2) else host).split('.')
        if (labels.any { !LABEL.matches(it) }) {
            return "$shown: host adi degil (harf, rakam ve tire; noktayla ayrilmis; en fazla bir bastaki '*.')"
        }
        if (wildcard) {
            val suffix = labels.joinToString(".").lowercase()
            if (labels.size < 2 || labels.last().all { it.isDigit() } || suffix in MULTI_LABEL_PUBLIC_SUFFIXES) {
                return "$shown: joker yalnizca kayitli bir alan adinin altinda olabilir (ornek *.example.com); " +
                    "uzantinin ya da bir adresin tamamini kapsayamaz"
            }
        }
        return null
    }
}

/**
 * The rest of the library's intake rules for a pin config
 * (`ssl/PinConfigValidator.validate`), applied wherever the server writes
 * pins: the pin editor, every route that adds a host or changes its
 * certificate, and the approval description of each. The server used to be
 * looser — `API.example.com` next to `api.example.com`, a hundred pins on one
 * host, pins that are not the Base64 of a SHA-256 — and published configs
 * every device then refused as a whole.
 *
 * One deliberate difference: a config with no entries at all is accepted
 * here. Removing the last host is an operator's choice, and devices keep the
 * config they have (the library refuses an empty one).
 */
object PinConfigRules {
    /** Most pin entries a config may carry (the library's `MAX_HOSTS`). */
    const val MAX_HOSTS = 2000

    /** Most pins one host may carry (the library's `MAX_PINS_PER_HOST`). */
    const val MAX_PINS_PER_HOST = 32

    /** Base64 of 32 bytes: 43 characters and one `=`. */
    private val PIN = Regex("[A-Za-z0-9+/]{43}=")

    /** Why [pin] is not the Base64 of a SHA-256, or null when it is. */
    fun pinError(pin: String?): String? = when {
        pin.isNullOrBlank() -> "bos olamaz"
        pin.length != 44 -> "gecersiz uzunluk ${pin.length} (beklenen: 44)"
        !PIN.matches(pin) -> "gecersiz Base64 formati (bir SHA-256'nin Base64'u: 43 karakter ve '=')"
        else -> null
    }

    /**
     * Every reason the entries of a config break the rules: the host pattern
     * ([HostPatternRules]), host names unique ignoring case, at most
     * [MAX_HOSTS] entries, 2–[MAX_PINS_PER_HOST] distinct pins per host, each
     * one a valid pin. Empty when the config may be published.
     */
    fun errors(pins: List<com.example.pinvault.server.model.HostPin>): List<String> {
        val errors = mutableListOf<String>()
        if (pins.size > MAX_HOSTS) errors.add("Config has ${pins.size} hosts (at most $MAX_HOSTS)")
        duplicateHosts(pins.map { it.hostname }).forEach { errors.add("$it: zaten mevcut (host adlari buyuk/kucuk harf ayirmaz)") }
        pins.forEach { pin -> errors.addAll(hostErrors(pin.hostname, pin.sha256)) }
        return errors
    }

    /** The rules for one entry: its host pattern and its pins. */
    fun hostErrors(hostname: String, pins: List<String>): List<String> {
        val errors = mutableListOf<String>()
        HostPatternRules.error(hostname)?.let { errors.add(it) }
        // Distinct pins: [X, X] is one pin written twice, not a backup.
        val distinct = pins.map { it.trim() }.filter { it.isNotEmpty() }.toSet().size
        if (distinct < 2) {
            errors.add("$hostname: en az 2 pin olmali (primary + backup) ve birbirinden farkli, mevcut: $distinct farkli pin")
        }
        if (pins.size > MAX_PINS_PER_HOST) errors.add("$hostname: ${pins.size} pin (en fazla $MAX_PINS_PER_HOST)")
        pins.forEachIndexed { index, pin -> pinError(pin)?.let { errors.add("$hostname[$index]: $it") } }
        return errors
    }

    /** Most managed trust roots a config may list (the library's `MAX_TRUST_ROOTS`). */
    const val MAX_TRUST_ROOTS = 64

    /**
     * Why the managed trust roots of a config break the rules: each a valid
     * pin, no duplicates, at most [MAX_TRUST_ROOTS]. Empty when fine.
     */
    fun trustRootErrors(roots: List<String>): List<String> {
        val errors = mutableListOf<String>()
        if (roots.size > MAX_TRUST_ROOTS) errors.add("trustRoots: ${roots.size} kok (en fazla $MAX_TRUST_ROOTS)")
        roots.forEachIndexed { index, root -> pinError(root)?.let { errors.add("trustRoots[$index]: $it") } }
        if (roots.toSet().size != roots.size) errors.add("trustRoots: ayni kok birden fazla kez listelenmis")
        return errors
    }

    /** Host names that appear more than once, compared as the library compares them (ignoring case). */
    fun duplicateHosts(hostnames: List<String>): List<String> =
        hostnames.groupBy { it.lowercase() }.filter { it.value.size > 1 }.map { it.value.first() }

    /** Whether [hostname] is already pinned among [pins], ignoring case. */
    fun pinned(pins: List<com.example.pinvault.server.model.HostPin>, hostname: String): Boolean =
        pins.any { it.hostname.equals(hostname, ignoreCase = true) }
}
