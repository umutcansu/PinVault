import Foundation

/// Host patterns → values, in the order they were given (wildcards are tried
/// in that order, as the Kotlin `LinkedHashMap` iterates). Keys are lower case.
struct PinHostMap<Value> {
    private(set) var keys: [String] = []
    private(set) var values: [String: Value] = [:]

    init() {}

    /// Sets `value` for `key` (lowercased). A key given twice keeps its first
    /// position and its last value, like `associate`.
    mutating func set(_ key: String, _ value: Value) {
        let name = key.lowercased()
        if values.updateValue(value, forKey: name) == nil { keys.append(name) }
    }

    subscript(key: String) -> Value? { values[key] }

    var isEmpty: Bool { keys.isEmpty }
    var count: Int { keys.count }

    /// The entries in order.
    var entries: [(key: String, value: Value)] { keys.map { ($0, values[$0]!) } }
}

extension PinHostMap: Sendable where Value: Sendable {}

/// Hostname → pin-set resolution for the pinning trust check. Kept apart from
/// ``DynamicSSLManager`` so it can be tested on its own.
///
/// Security boundary (H-01): a certificate pinned for host A must NOT validate
/// for host B even when both come from the same config. Pre-V2 the library
/// flattened every host's hashes into one set, so a leak of any one host's
/// private key let an attacker MITM every other pinned host in the config.
/// Per-host scoping closes that path.
enum PinHostMatcher {

    /// A per-host map of `(hostname, value)` pairs. Hostnames are lowercased
    /// for case-insensitive lookup; wildcard patterns like `*.example.com` are
    /// kept verbatim and resolved at lookup time by ``match(_:_:port:)``.
    static func build<Value>(_ entries: [(String, Value)]) -> PinHostMap<Value> {
        var map = PinHostMap<Value>()
        for (host, value) in entries { map.set(host, value) }
        return map
    }

    /// The value for `hostname`:
    ///   1. with `port`, an exact `host:port` entry, then a `*.suffix:port` wildcard;
    ///   2. the exact (case-insensitive) hostname;
    ///   3. a port-less wildcard covering exactly one label (`*.example.com`
    ///      matches `api.example.com`, not `example.com` nor `a.b.example.com`).
    ///
    /// A `host:port` entry pins that one listener and nothing else: when it
    /// exists it is the ONLY set considered for that port, and it never applies
    /// to the host's other ports. That lets one listener (a certificate-renewal
    /// door pinned to the backend's own CA) carry a different trust anchor than
    /// the rest of the host without widening what the other ports accept.
    ///
    /// Wildcard suffixes must contain a dot — `*.com` would let one
    /// misconfigured entry authorize a whole TLD; such patterns are skipped
    /// here, and ``PinConfigValidator`` refuses them at intake.
    ///
    /// Nil when nothing matches: callers treat nil as a hard reject.
    static func match<Value>(_ map: PinHostMap<Value>, _ hostname: String, port: Int? = nil) -> Value? {
        let host = hostname.lowercased()
        if let port, port > 0 {
            if let value = map["\(host):\(port)"] { return value }
            if let value = matchWildcard(map, host, portSuffix: ":\(port)") { return value }
        }
        if let value = map[host] { return value }
        return matchWildcard(map, host, portSuffix: "")
    }

    /// The value of a `*.suffix` + `portSuffix` pattern covering exactly one
    /// label of `host`. With an empty `portSuffix` only port-less patterns
    /// count: a `*.example.com:443` entry never applies to another port.
    private static func matchWildcard<Value>(_ map: PinHostMap<Value>, _ host: String, portSuffix: String) -> Value? {
        for pattern in map.keys where pattern.hasPrefix("*.") {
            let withoutPort: Substring
            if portSuffix.isEmpty {
                if pattern.contains(":") { continue }
                withoutPort = Substring(pattern)
            } else {
                guard pattern.hasSuffix(portSuffix) else { continue }
                withoutPort = pattern.dropLast(portSuffix.count)
            }
            let suffix = withoutPort.dropFirst(2)
            if !suffix.contains(".") || suffix.contains(":") { continue }
            guard host.hasSuffix("." + suffix) else { continue }
            let left = host.dropLast(suffix.count + 1)
            if !left.isEmpty, !left.contains(".") { return map[pattern] }
        }
        return nil
    }
}
