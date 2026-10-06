import Foundation

/// What a pin config may contain, checked before anything else looks at it:
/// at intake (a fetched config, static pins) and again when a stored config
/// is read back. A config with one bad entry is refused as a whole.
enum PinConfigValidator {

    /// Longest accepted host pattern, the `*.` prefix included and the port excluded.
    static let maxHostnameLength = 253
    /// Most pin entries a config may carry.
    static let maxHosts = 2000
    /// Most pins one host may carry.
    static let maxPinsPerHost = 32
    /// Most managed trust roots a config may list.
    static let maxTrustRoots = 64

    /// Two-label registries a wildcard must not sit directly under (on top of
    /// the "at least two labels after `*.`" rule).
    static let multiLabelPublicSuffixes: Set<String> = [
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
        "azurewebsites.net", "cloudfront.net", "netlify.app", "vercel.app", "pages.dev", "workers.dev",
    ]

    /// Throws ``PinVaultError/invalidPinFormat(message:cause:)`` unless `config`
    /// has at least one entry and every entry is well-formed: a valid host
    /// pattern, no host named twice, a non-negative version, and at least two
    /// different pins that are each the Base64 of a SHA-256.
    static func validate(_ config: CertificateConfig) throws {
        let pins = config.pins
        if pins.isEmpty { throw invalid("Config must contain at least one pin entry") }
        if pins.count > maxHosts { throw invalid("Config has \(pins.count) pin entries (at most \(maxHosts))") }

        let roots = config.trustRoots
        if roots.count > maxTrustRoots {
            throw invalid("Config lists \(roots.count) trust roots (at most \(maxTrustRoots))")
        }
        for (index, root) in roots.enumerated() {
            if let error = pinError(root) { throw invalid("Trust root at index \(index) \(error)") }
        }
        if Set(roots).count != roots.count { throw invalid("A trust root is listed more than once") }

        var seen = Set<String>()
        for pin in pins {
            let hostname = pin.hostname
            if let error = hostPatternError(hostname) { throw invalid(error) }
            if !seen.insert(hostname.lowercased()).inserted {
                throw invalid("Host \(printable(hostname)) is listed more than once")
            }
            if pin.version < 0 {
                throw invalid("Host \(printable(hostname)) has a negative version (\(pin.version))")
            }
            let hashes = pin.sha256
            if hashes.count < 2 {
                throw invalid("Host \(printable(hostname)) must have at least 2 pins (primary + backup)")
            }
            if hashes.count > maxPinsPerHost {
                throw invalid("Host \(printable(hostname)) has \(hashes.count) pins (at most \(maxPinsPerHost))")
            }
            // The same hash twice gives a rotation nothing to fall back on.
            if Set(hashes).count < 2 {
                throw invalid(
                    "Host \(printable(hostname)) must have at least 2 different pins (primary + backup); the same pin is listed twice"
                )
            }
            for (index, hash) in hashes.enumerated() {
                if let error = pinError(hash) { throw invalid("Hash at index \(index) for \(printable(hostname)) \(error)") }
            }
        }
    }

    /// Nil when `pattern` is a host a pin entry may name, else why it is not.
    /// Accepted: LDH labels joined by dots (IPv4 too), optionally one leading
    /// `*.` for exactly one label, optionally `:port` (1–65535), at most
    /// ``maxHostnameLength`` characters without the port. A wildcard needs two
    /// labels after it and must not sit directly under a public suffix. No IPv6 literals.
    static func hostPatternError(_ pattern: String?) -> String? {
        guard let pattern, !pattern.isEmpty else { return "A pin entry has no hostname" }
        let shown = printable(pattern)
        let host: Substring
        if let colon = pattern.lastIndex(of: ":") {
            host = pattern[..<colon]
            let port = pattern[pattern.index(after: colon)...]
            guard isPort(port), let value = Int(port), value <= 65_535 else {
                return "Hostname \(shown) has an invalid port (1–65535, digits only)"
            }
        } else {
            host = Substring(pattern)
        }
        // Kotlin counts UTF-16 units; for valid names (ASCII) that is the character count.
        if host.isEmpty || host.utf16.count > maxHostnameLength {
            return "Hostname \(shown) must be 1–\(maxHostnameLength) characters long"
        }
        let wildcard = host.hasPrefix("*.")
        let labels = (wildcard ? host.dropFirst(2) : host).split(separator: ".", omittingEmptySubsequences: false)
        if labels.contains(where: { !isLabel($0) }) {
            return "Hostname \(shown) is not a host name: labels are letters, digits and hyphens, joined by dots, " +
                "with at most one leading '*.'"
        }
        if wildcard {
            let suffix = labels.joined(separator: ".").lowercased()
            if labels.count < 2 || labels.last!.allSatisfy(\.isASCIIDigit) || multiLabelPublicSuffixes.contains(suffix) {
                return "Hostname \(shown) is a wildcard over a public suffix or an address; a wildcard needs a " +
                    "registered domain after '*.' (e.g. *.example.com)"
            }
        }
        return nil
    }

    /// Nil when `hash` is the Base64 of a SHA-256 (44 characters), else what is wrong with it.
    static func pinError(_ hash: String?) -> String? {
        guard let hash, !hash.isBlank else { return "is blank" }
        let length = hash.utf16.count
        if length != 44 { return "has invalid length: \(length) (expected 44)" }
        let bytes = Array(hash.utf8)
        guard bytes.count == 44, bytes[43] == UInt8(ascii: "="), bytes[0..<43].allSatisfy(isBase64Char) else {
            return "is not valid Base64 of a SHA-256"
        }
        return nil
    }

    /// `[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?`
    private static func isLabel(_ label: Substring) -> Bool {
        let bytes = Array(label.utf8)
        guard (1...63).contains(bytes.count), bytes.count == label.count else { return false }
        guard isAlnum(bytes.first!), isAlnum(bytes.last!) else { return false }
        return bytes.allSatisfy { isAlnum($0) || $0 == UInt8(ascii: "-") }
    }

    /// `[1-9][0-9]{0,4}`
    private static func isPort(_ port: Substring) -> Bool {
        let bytes = Array(port.utf8)
        guard (1...5).contains(bytes.count), bytes.count == port.count else { return false }
        guard bytes[0] >= UInt8(ascii: "1"), bytes[0] <= UInt8(ascii: "9") else { return false }
        return bytes.allSatisfy { $0 >= UInt8(ascii: "0") && $0 <= UInt8(ascii: "9") }
    }

    private static func isAlnum(_ c: UInt8) -> Bool {
        (c >= UInt8(ascii: "a") && c <= UInt8(ascii: "z")) || (c >= UInt8(ascii: "A") && c <= UInt8(ascii: "Z"))
            || (c >= UInt8(ascii: "0") && c <= UInt8(ascii: "9"))
    }

    private static func isBase64Char(_ c: UInt8) -> Bool {
        isAlnum(c) || c == UInt8(ascii: "+") || c == UInt8(ascii: "/")
    }

    /// `value` made safe for a log line or an error message: no control characters, bounded.
    static func printable(_ value: String) -> String {
        let scalars = Array(value.unicodeScalars)
        let head = scalars.prefix(80).map { scalar -> String in
            scalar.properties.generalCategory == .control ? "?" : String(scalar)
        }.joined()
        return "'" + head + (scalars.count > 80 ? "…" : "") + "'"
    }

    private static func invalid(_ message: String) -> PinVaultError {
        .invalidPinFormat(message: message)
    }
}
