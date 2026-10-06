import Foundation
#if canImport(UIKit)
import UIKit
#endif

/// The single source of the device id PinVault presents to a Config API
/// (`X-Device-Id` on scoped config fetches and vault downloads, `deviceUid` at
/// enrollment); they must agree or the server-side ACL silently fails to match.
///
/// iOS: `UIDevice.identifierForVendor`, lowercased — stable across data wipes,
/// new after a reinstall. A soft identifier, not an authentication factor.
enum DeviceIdentity {

    /// nil = not read yet; `.some(nil)` = read, unavailable.
    private static let cache = Locked<String??>(nil)

    /// The device id, or nil when the platform gives none (macOS test runs).
    /// Reads `UIDevice` on the main thread once and caches it.
    static func deviceId() -> String? {
        if let cached = cache.get() { return cached }
        let id = readVendorId()
        cache.set(.some(id))
        return id
    }

    /// Reads the id from an async context without blocking a thread on the main queue.
    static func warmUp() async {
        if cache.get() != nil { return }
        #if canImport(UIKit) && !os(watchOS)
        let id = await MainActor.run { UIDevice.current.identifierForVendor?.uuidString.lowercased() }
        cache.set(.some(id))
        #else
        cache.set(.some(nil))
        #endif
    }

    private static func readVendorId() -> String? {
        #if canImport(UIKit) && !os(watchOS)
        if Thread.isMainThread {
            return MainActor.assumeIsolated { UIDevice.current.identifierForVendor?.uuidString.lowercased() }
        }
        return DispatchQueue.main.sync {
            MainActor.assumeIsolated { UIDevice.current.identifierForVendor?.uuidString.lowercased() }
        }
        #else
        return nil
        #endif
    }
}

/// Static device labels: the iOS counterparts of `Build.MANUFACTURER` / `Build.MODEL`.
enum DeviceInfo {
    static let manufacturer = "Apple"

    /// The machine identifier (`iPhone17,1`); on the simulator the simulated
    /// device's (`SIMULATOR_MODEL_IDENTIFIER`); on a Mac `hw.model`.
    static let model: String = {
        if let simulated = ProcessInfo.processInfo.environment["SIMULATOR_MODEL_IDENTIFIER"], !simulated.isEmpty {
            return simulated
        }
        #if os(macOS)
        return sysctlString("hw.model") ?? "Mac"
        #else
        return sysctlString("hw.machine") ?? "unknown"
        #endif
    }()

    /// `major.minor[.patch]` of the running OS.
    static var osVersion: String {
        let version = ProcessInfo.processInfo.operatingSystemVersion
        return version.patchVersion == 0
            ? "\(version.majorVersion).\(version.minorVersion)"
            : "\(version.majorVersion).\(version.minorVersion).\(version.patchVersion)"
    }

    private static func sysctlString(_ name: String) -> String? {
        var size = 0
        guard sysctlbyname(name, nil, &size, nil, 0) == 0, size > 0 else { return nil }
        var buffer = [CChar](repeating: 0, count: size)
        guard sysctlbyname(name, &buffer, &size, nil, 0) == 0 else { return nil }
        return String(decoding: buffer.prefix(while: { $0 != 0 }).map { UInt8(bitPattern: $0) }, as: UTF8.self)
    }
}
