import Foundation

/// Binds a signed pin config to the request it answers (M6; wire format in
/// SERVER_IMPLEMENTATION_GUIDE.md §3, `view`). Kotlin `crypto/ConfigViewBinding`.
///
/// A server signs narrowed views of a scope's config — `?hosts=` from
/// `wantPinsFor(...)`, a device's host ACL from `X-Device-Id`, the config
/// inside an attestation answer — and writes into the signed payload what
/// narrowed it:
///
/// ```json
/// "view": {"hosts": ["api.example.com", "cdn.example.com"], "deviceId": "a1b2c3"}
/// ```
///
/// `hosts` is the REQUESTED set in canonical form (``canonicalHosts(_:)``),
/// `deviceId` the device id the request claimed; either may be absent, and a
/// full (un-narrowed) config carries no `view` at all.
///
/// Decision (``check(payload:expected:)``), made from the block's own request alone:
///
/// | request                     | payload `view`                                   | outcome |
/// |-----------------------------|--------------------------------------------------|---------|
/// | full (no `wantPinsFor`)     | absent                                           | accept  |
/// | full                        | present (any)                                    | REFUSE  |
/// | scoped (hosts H, device D)  | `hosts` = canonical(H), `deviceId` = D (absent when D is nil) | accept |
/// | scoped                      | other hosts, other/missing/extra device id, unknown key, malformed | REFUSE |
/// | scoped                      | absent                                           | accept (a full view: a server before 2.9.0, or the full config) |
///
/// The last row: a 2.9.0+ server never signs a narrowed view without the
/// field, so a view-less payload from it is the full config — more pins than
/// the ACL would give, never fewer (the low-harm direction). Refusing it would
/// cut scoped apps off older servers and custom backends that do not write the
/// field yet.
///
/// Strings are compared by their Unicode scalars, not with Swift's `==`
/// (which treats canonically equivalent strings as equal): Kotlin compares
/// UTF-16 code units, and both sides must make the same decision.
enum ConfigViewBinding {

    /// The payload field.
    static let field = "view"

    private static let log = PinVaultLog.tag("ConfigViewBinding")

    /// What a scoped request asked for: the canonical host set and the device
    /// ids its view may name (one for a fetch; for a stored view also the form
    /// an attestation request uses, which differs for a device without a usable
    /// id). `nil` in ``deviceIds`` = "no device id was sent". A full request is
    /// represented by no `Expected` at all (nil).
    struct Expected: Sendable, CustomStringConvertible {
        let hosts: [String]
        /// Distinct, in the order given.
        let deviceIds: [String?]

        init(hosts: [String], deviceIds: [String?]) {
            self.hosts = ConfigViewBinding.canonicalHosts(hosts)
            var distinct: [String?] = []
            for id in deviceIds where !distinct.contains(where: { ConfigViewBinding.same($0, id) }) {
                distinct.append(id)
            }
            self.deviceIds = distinct
        }

        func accepts(deviceId: String?) -> Bool {
            deviceIds.contains { ConfigViewBinding.same($0, deviceId) }
        }

        var description: String {
            "hosts=[" + hosts.joined(separator: ",") + "], deviceId=" +
                deviceIds.map { $0.map { "'\($0.kotlinTake(64))'" } ?? "(none)" }.joined(separator: "|")
        }
    }

    /// The request a block makes: nil (full) without `wantPinsFor`, else its
    /// canonical set with `deviceIds`.
    static func expected(wantPinsFor: [String], deviceIds: String?...) -> Expected? {
        wantPinsFor.isEmpty ? nil : Expected(hosts: wantPinsFor, deviceIds: deviceIds)
    }

    /// ASCII whitespace the canonical form trims: U+0020, U+0009, U+000A, U+000D, U+000B, U+000C.
    private static func isTrimmed(_ scalar: Unicode.Scalar) -> Bool {
        switch scalar.value {
        case 0x20, 0x09, 0x0A, 0x0D, 0x0B, 0x0C: return true
        default: return false
        }
    }

    /// The canonical host set: every entry split at `,` (the server reads
    /// `?hosts=` that way), ASCII whitespace trimmed, empty names dropped,
    /// ASCII `A-Z` lower-cased (nothing else changes: no locale rules),
    /// duplicates removed, sorted by Unicode code point. Works on Unicode
    /// scalars throughout: a `,` followed by a combining mark is one Swift
    /// `Character`, but still a separator here, as in Kotlin.
    static func canonicalHosts(_ hosts: [String]) -> [String] {
        var seen = Set<[UInt32]>()
        var names: [[UInt32]] = []
        for host in hosts {
            for part in host.unicodeScalars.split(separator: ",", omittingEmptySubsequences: false) {
                var slice = part[...]
                while let first = slice.first, isTrimmed(first) { slice = slice.dropFirst() }
                while let last = slice.last, isTrimmed(last) { slice = slice.dropLast() }
                if slice.isEmpty { continue }
                let name = slice.map { scalar -> UInt32 in
                    (0x41...0x5A).contains(scalar.value) ? scalar.value + 32 : scalar.value
                }
                if seen.insert(name).inserted { names.append(name) }
            }
        }
        return names.sorted { $0.lexicographicallyPrecedes($1) }.map { values in
            var view = String.UnicodeScalarView()
            for value in values { if let scalar = Unicode.Scalar(value) { view.append(scalar) } }
            return String(view)
        }
    }

    /// Throws ``PinVaultError/configViewMismatch(message:)`` when the signed
    /// `payload` does not answer `expected` (nil = the full config); see the
    /// table above. Call after the signature verified and before anything is
    /// stored, applied or compared for replay.
    static func check(payload: String, expected: Expected?) throws {
        guard let object = (try? JSONSerialization.jsonObject(with: Data(payload.utf8), options: [.fragmentsAllowed])) as? [String: Any] else {
            throw PinVaultError.configViewMismatch(message: "Signed config rejected: its payload is not a JSON object.")
        }
        let view: Any? = object[field].flatMap { $0 is NSNull ? nil : $0 }
        guard let expected else {
            if let view {
                throw PinVaultError.configViewMismatch(message:
                    "Signed config rejected: it is a narrowed view (\(describe(view))), but this block asks for " +
                        "the full config. Applying it would drop the pins of every host it leaves out."
                )
            }
            return
        }
        guard let view else {
            log.w("Signed config carries no '\(field)' — a full view or a server before 2.9.0; accepted for a scoped block")
            return
        }
        guard let members = view as? [String: Any] else { throw mismatch(expected, view, "'\(field)' is not an object") }
        // A narrowing this client does not understand: it cannot tell what was left out.
        if let unknown = members.keys.sorted().first(where: { !same($0, "hosts") && !same($0, "deviceId") }) {
            throw mismatch(expected, view, "unknown key '\(unknown.kotlinTake(32))'")
        }
        guard let hosts = members["hosts"].flatMap({ $0 is NSNull ? nil : $0 }) else {
            throw mismatch(expected, view, "it names no host set")
        }
        guard let array = hosts as? [Any] else { throw mismatch(expected, view, "'hosts' is not an array") }
        var names: [String] = []
        for element in array {
            guard let name = element as? String else { throw mismatch(expected, view, "'hosts' holds a non-string") }
            names.append(name)
        }
        // Compared as sent: the server writes the canonical form, so anything else is another request.
        if names.count != expected.hosts.count || zip(names, expected.hosts).contains(where: { !same($0, $1) }) {
            throw mismatch(expected, view, "another host set")
        }
        var deviceId: String?
        if let raw = members["deviceId"].flatMap({ $0 is NSNull ? nil : $0 }) {
            guard let id = raw as? String else { throw mismatch(expected, view, "'deviceId' is not a string") }
            deviceId = id
        }
        if !expected.accepts(deviceId: deviceId) {
            throw mismatch(expected, view, deviceId == nil ? "it names no device id" : "another device id")
        }
    }

    /// Exact equality: the same Unicode scalars (Kotlin `String.equals`).
    static func same(_ a: String?, _ b: String?) -> Bool {
        switch (a, b) {
        case (nil, nil): return true
        case let (a?, b?): return a.unicodeScalars.elementsEqual(b.unicodeScalars)
        default: return false
        }
    }

    private static func mismatch(_ expected: Expected, _ view: Any, _ why: String) -> PinVaultError {
        .configViewMismatch(message:
            "Signed config rejected: it answers another request (\(why)). Asked for \(expected); the payload's view is \(describe(view))."
        )
    }

    private static func describe(_ view: Any) -> String {
        let data = try? JSONSerialization.data(withJSONObject: view, options: [.fragmentsAllowed, .sortedKeys, .withoutEscapingSlashes])
        let text = data.map { String(decoding: $0, as: UTF8.self) } ?? String(describing: view)
        return text.utf16.count > 200 ?text.kotlinTake(200) + "…" : text
    }
}
