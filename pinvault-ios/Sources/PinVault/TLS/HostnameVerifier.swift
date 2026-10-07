import Foundation

/// The hostname check of OkHttp's `OkHostnameVerifier`, which every client the
/// Android library builds runs after the handshake: the leaf's
/// `subjectAltName` must name the host — a DNS name (RFC 6125 single-label
/// wildcards, case-insensitive) or, for an IP address literal, an iPAddress
/// entry. The subject CN is never consulted.
///
/// Done here on the parsed certificate rather than with Apple's SSL policy:
/// that policy adds Apple-specific rules (validity caps, EKU, key sizes) that
/// have nothing to do with a pinned host and would refuse certificates
/// Android accepts.
enum HostnameVerifier {

    /// True when `certificate` is issued for `host`. An empty or non-ASCII host never matches.
    static func verify(_ host: String, _ certificate: X509Certificate) -> Bool {
        guard !host.isEmpty, host.allSatisfy(\.isASCII) else { return false }
        if canParseAsIPAddress(host) {
            guard let address = ipAddressBytes(host) else { return false }
            return certificate.ipAddresses.contains { canonical($0) == address }
        }
        let hostname = host.lowercased()
        return certificate.dnsNames.contains { verify(hostname: hostname, pattern: $0) }
    }

    /// The SAN entries OkHttp lists in its "not verified" message.
    static func allSubjectAltNames(_ certificate: X509Certificate) -> [String] {
        certificate.dnsNames + certificate.ipAddressStrings
    }

    /// OkHttp's `verifyHostname(hostname, pattern)`; `hostname` is lower case.
    static func verify(hostname: String, pattern rawPattern: String) -> Bool {
        var hostname = hostname
        var pattern = rawPattern
        if hostname.isEmpty || hostname.hasPrefix(".") || hostname.hasSuffix("..") { return false }
        if pattern.isEmpty || pattern.hasPrefix(".") || pattern.hasSuffix("..") { return false }
        guard pattern.allSatisfy(\.isASCII) else { return false }
        // Absolute names, so "example.com" and "example.com." compare equal.
        if !hostname.hasSuffix(".") { hostname += "." }
        if !pattern.hasSuffix(".") { pattern += "." }
        pattern = pattern.lowercased()

        if !pattern.contains("*") { return hostname == pattern }

        // Wildcard: only "*." as the whole left-most label, never elsewhere.
        if !pattern.hasPrefix("*.") || pattern.dropFirst().contains("*") { return false }
        // The asterisk matches one or more characters.
        if hostname.count < pattern.count { return false }
        // "*." alone would cover every single-label name.
        if pattern == "*." { return false }
        let suffix = pattern.dropFirst()  // ".example.com."
        if !hostname.hasSuffix(suffix) { return false }
        // The asterisk must not span labels.
        let prefix = hostname.dropLast(suffix.count)
        if prefix.contains(".") { return false }
        return true
    }

    /// OkHttp's `canParseAsIpAddress`: `[0-9a-fA-F]*:[0-9a-fA-F:.]*` or `[\d.]+`.
    static func canParseAsIPAddress(_ host: String) -> Bool {
        let bytes = Array(host.utf8)
        guard !bytes.isEmpty else { return false }
        if bytes.allSatisfy({ isDigit($0) || $0 == UInt8(ascii: ".") }) { return true }
        guard let colon = bytes.firstIndex(of: UInt8(ascii: ":")) else { return false }
        return bytes[..<colon].allSatisfy(isHex)
            && bytes[(colon + 1)...].allSatisfy { isHex($0) || $0 == UInt8(ascii: ":") || $0 == UInt8(ascii: ".") }
    }

    /// The address bytes of an IPv4 / IPv6 literal (brackets allowed), IPv4-mapped
    /// IPv6 reduced to IPv4 (OkHttp's `toCanonicalHost`); nil when it is not one.
    static func ipAddressBytes(_ text: String) -> Data? {
        var literal = text
        if literal.hasPrefix("["), literal.hasSuffix("]") { literal = String(literal.dropFirst().dropLast()) }
        var v4 = in_addr()
        if inet_pton(AF_INET, literal, &v4) == 1 {
            return withUnsafeBytes(of: &v4) { Data($0) }
        }
        var v6 = in6_addr()
        if inet_pton(AF_INET6, literal, &v6) == 1 {
            return canonical(withUnsafeBytes(of: &v6) { Data($0) })
        }
        return nil
    }

    /// IPv4-mapped IPv6 (`::ffff:a.b.c.d`) → the 4 IPv4 bytes; anything else as it is.
    static func canonical(_ address: Data) -> Data {
        let bytes = [UInt8](address)
        if bytes.count == 16, bytes[0..<10].allSatisfy({ $0 == 0 }), bytes[10] == 0xFF, bytes[11] == 0xFF {
            return Data(bytes[12..<16])
        }
        return address
    }

    private static func isDigit(_ c: UInt8) -> Bool { c >= UInt8(ascii: "0") && c <= UInt8(ascii: "9") }

    private static func isHex(_ c: UInt8) -> Bool {
        isDigit(c) || (c >= UInt8(ascii: "a") && c <= UInt8(ascii: "f")) || (c >= UInt8(ascii: "A") && c <= UInt8(ascii: "F"))
    }
}
