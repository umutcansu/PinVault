import Foundation
import Security

/// A copy of a config store's replay watermarks and trusted-clock reference
/// outside the app's container.
///
/// The watermarks (highest accepted `issuedAt`, per-host versions) and the
/// clock reference live in the store's plist, inside the container. Whoever
/// can write the container (a jailbroken device, a restored backup of it) can
/// put an older copy back, and with it the device would accept an older,
/// still-valid signed config again. Keychain items are not part of the
/// container, so the store also writes these values here and reads back the
/// higher of the two: restoring the container alone no longer moves them back.
/// (Android has no such place; see `ATTESTATION.md` and `pinvault-ios/README.md`.)
protocol WatermarkMirror: Sendable {
    /// The mirrored values; empty when nothing was mirrored, nil when the copy cannot be read now.
    func read() -> MirroredWatermarks?
    /// False when the copy could not be written (it keeps its old values).
    @discardableResult func write(_ values: MirroredWatermarks) -> Bool
}

/// The mirrored values; zero / empty when nothing was mirrored.
struct MirroredWatermarks: Sendable, Equatable {
    var issuedAt: Int64 = 0
    var versions: [String: Int] = [:]
    var clock: Int64 = 0
    /// The signing-key set the watermarks were last reset for (a reset lowers them here too).
    var keySetVersion: Int?
    /// Fingerprint of the compiled-in trust anchors the watermarks were set under.
    var anchors: String?
    /// The key-set floor (the block's copy only): the newest signing-key set
    /// applied, under the recovery keys whose fingerprint is `floorAnchors`.
    var floorVersion: Int?
    var floorAnchors: String?
}

/// No mirror: tests, and anywhere the Keychain is not used.
struct NoWatermarkMirror: WatermarkMirror {
    func read() -> MirroredWatermarks? { MirroredWatermarks() }
    @discardableResult func write(_ values: MirroredWatermarks) -> Bool { true }
}

/// The mirror as one Keychain generic password per store namespace (service
/// `io.github.umutcansu.pinvault.watermarks`, account = the namespace),
/// `AfterFirstUnlockThisDeviceOnly`, a small JSON object. Where the Keychain
/// refuses the process (an unsigned test run) it reads empty and writes nothing.
final class KeychainWatermarkMirror: WatermarkMirror, @unchecked Sendable {
    static let service = "io.github.umutcansu.pinvault.watermarks"

    private let account: String
    private let log = PinVaultLog.tag("WatermarkMirror")

    init(account: String) {
        self.account = account
    }

    private var query: [CFString: Any] {
        [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: Self.service,
            kSecAttrAccount: account,
            kSecUseDataProtectionKeychain: true,
        ]
    }

    func read() -> MirroredWatermarks? {
        var lookup = query
        lookup[kSecReturnData] = true
        lookup[kSecMatchLimit] = kSecMatchLimitOne
        var item: CFTypeRef?
        let status = SecItemCopyMatching(lookup as CFDictionary, &item)
        // Nothing mirrored yet, or no Keychain for this process (unsigned test runs): empty.
        if status == errSecItemNotFound || status == errSecMissingEntitlement { return MirroredWatermarks() }
        guard status == errSecSuccess, let data = item as? Data else {
            // Unreadable now (a locked device, a Keychain error): the caller neither trusts nor rewrites it.
            log.w("Watermark mirror [\(account)] cannot be read (OSStatus \(status))")
            return nil
        }
        // Read fresh every time: an app extension sharing the access group may have written it.
        return Self.decode(data)
    }

    @discardableResult func write(_ values: MirroredWatermarks) -> Bool {
        let data = Self.encode(values)
        var status = SecItemUpdate(query as CFDictionary, [kSecValueData: data] as CFDictionary)
        if status == errSecItemNotFound {
            var add = query
            add[kSecValueData] = data
            add[kSecAttrAccessible] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            status = SecItemAdd(add as CFDictionary, nil)
        }
        // No Keychain for this process (unsigned test runs): nothing to keep, nothing lost.
        if status == errSecSuccess || status == errSecMissingEntitlement { return true }
        log.w("Watermark mirror [\(account)] cannot be written (OSStatus \(status))")
        return false
    }

    static func encode(_ values: MirroredWatermarks) -> Data {
        var members: [String] = [
            "\"issuedAt\":\(values.issuedAt)",
            "\"clock\":\(values.clock)",
            "\"versions\":{" + values.versions.sorted { $0.key < $1.key }.map { "\(JSONText.string($0.key)):\($0.value)" }.joined(separator: ",") + "}",
        ]
        if let keySet = values.keySetVersion { members.append("\"keySetVersion\":\(keySet)") }
        if let anchors = values.anchors { members.append("\"anchors\":\(JSONText.string(anchors))") }
        if let floor = values.floorVersion { members.append("\"floorVersion\":\(floor)") }
        if let floorAnchors = values.floorAnchors { members.append("\"floorAnchors\":\(JSONText.string(floorAnchors))") }
        return Data(("{" + members.joined(separator: ",") + "}").utf8)
    }

    static func decode(_ data: Data) -> MirroredWatermarks {
        guard let json = LenientJSON.object(data) else { return MirroredWatermarks() }
        var values = MirroredWatermarks()
        values.issuedAt = LenientJSON.long(json, "issuedAt", 0)
        values.clock = LenientJSON.long(json, "clock", 0)
        if let versions = json["versions"] as? [String: Any] {
            for (host, version) in versions {
                if let number = version as? NSNumber { values.versions[host] = number.intValue }
            }
        }
        if let keySet = json["keySetVersion"] as? NSNumber { values.keySetVersion = keySet.intValue }
        if let anchors = json["anchors"] as? String { values.anchors = anchors }
        if let floor = json["floorVersion"] as? NSNumber { values.floorVersion = floor.intValue }
        if let floorAnchors = json["floorAnchors"] as? String { values.floorAnchors = floorAnchors }
        return values
    }
}
