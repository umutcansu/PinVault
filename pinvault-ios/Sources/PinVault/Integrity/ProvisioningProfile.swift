import Foundation

/// What the probes read from `embedded.mobileprovision`, the provisioning
/// profile Xcode embeds in development, ad hoc and enterprise builds (App
/// Store and TestFlight builds have none). The file is a CMS envelope around
/// an XML property list; the plist is cut out and parsed, the signature is
/// not checked (the probe is a measurement, the server decides).
struct ProvisioningProfile: Sendable, Equatable {
    /// `TeamIdentifier[0]`: the Apple team id.
    var teamIdentifier: String?
    /// `ApplicationIdentifierPrefix[0]` (the App ID prefix; usually the team id).
    var applicationIdentifierPrefix: String?
    /// `Entitlements.application-identifier` (`TEAMID.bundle.id`).
    var applicationIdentifier: String?
    /// `Entitlements.get-task-allow`; nil when the profile does not say.
    var getTaskAllow: Bool?

    /// The team id the profile names: `TeamIdentifier`, else the App ID prefix,
    /// else the prefix of `application-identifier` — each only when it is a
    /// 10-character team id.
    var teamId: String? {
        let candidates = [teamIdentifier, applicationIdentifierPrefix, applicationIdentifier.flatMap { $0.split(separator: ".").first.map(String.init) }]
        return candidates.compactMap { $0 }.first(where: TeamId.isValid)
    }

    /// The profile in `data` (the raw `.mobileprovision` bytes or a bare plist); nil when there is none.
    static func parse(_ data: Data) -> ProvisioningProfile? {
        guard let plist = plistBytes(data),
              let object = try? PropertyListSerialization.propertyList(from: plist, options: [], format: nil),
              let dictionary = object as? [String: Any] else { return nil }
        let entitlements = dictionary["Entitlements"] as? [String: Any] ?? [:]
        return ProvisioningProfile(
            teamIdentifier: (dictionary["TeamIdentifier"] as? [String])?.first,
            applicationIdentifierPrefix: (dictionary["ApplicationIdentifierPrefix"] as? [String])?.first,
            applicationIdentifier: entitlements["application-identifier"] as? String,
            getTaskAllow: entitlements["get-task-allow"] as? Bool
        )
    }

    /// From `<?xml` to the end of `</plist>`; the whole input when it starts with a plist.
    private static func plistBytes(_ data: Data) -> Data? {
        let bytes = [UInt8](data)
        guard let start = find(Array("<?xml".utf8), in: bytes, from: 0) ?? find(Array("<plist".utf8), in: bytes, from: 0) else {
            // A binary plist is not what Xcode embeds, but parse it if that is what is there.
            return bytes.starts(with: Array("bplist".utf8)) ? data : nil
        }
        let endTag = Array("</plist>".utf8)
        guard let end = find(endTag, in: bytes, from: start) else { return nil }
        return Data(bytes[start..<(end + endTag.count)])
    }

    private static func find(_ needle: [UInt8], in haystack: [UInt8], from: Int) -> Int? {
        guard !needle.isEmpty, haystack.count >= needle.count, from <= haystack.count - needle.count else { return nil }
        var index = from
        while index <= haystack.count - needle.count {
            if haystack[index] == needle[0], Array(haystack[index..<(index + needle.count)]) == needle { return index }
            index += 1
        }
        return nil
    }
}

/// Apple team ids: ten upper-case letters or digits.
enum TeamId {
    static func isValid(_ value: String) -> Bool {
        value.utf8.count == 10 && value.utf8.allSatisfy { ($0 >= 0x30 && $0 <= 0x39) || ($0 >= 0x41 && $0 <= 0x5A) }
    }

    /// The team id at the front of a keychain access group (`ABCDE12345.com.example.app`), or nil.
    static func fromAccessGroup(_ group: String?) -> String? {
        guard let prefix = group?.split(separator: ".", maxSplits: 1).first.map(String.init), isValid(prefix) else { return nil }
        return prefix
    }
}
