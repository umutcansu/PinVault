import Darwin
import Foundation
import MachO
import Security
#if canImport(UIKit)
import UIKit
#endif

/// Everything the probes read from the device, as replaceable readers: the
/// live ones (``live``) on a device, fakes in tests that simulate a
/// jailbroken, hooked or debugged one. A reader may throw; the probe that
/// uses it then reports `error:<probe>`.
struct IntegrityProbeInputs: Sendable {
    var fileExists: @Sendable (String) -> Bool
    /// The sandbox-escape test: true when a file could be written directly under `/private`.
    var canWriteOutsideSandbox: @Sendable () throws -> Bool
    var environment: @Sendable () -> [String: String]
    /// `targetEnvironment(simulator)`.
    var isSimulatorBuild: Bool
    /// The library was built with `DEBUG`.
    var isDebugBuild: Bool
    /// The simulator and macOS see the Mac's own file system.
    var onMacHost: Bool
    /// `sysctl` `P_TRACED` of this process.
    var isTraced: @Sendable () throws -> Bool
    var loadedImages: @Sendable () -> [String]
    /// True when `127.0.0.1:<port>` accepts a TCP connection.
    var localPortOpen: @Sendable (UInt16) -> Bool
    /// The embedded provisioning profile; nil when the app has none.
    var provisioningProfile: @Sendable () throws -> ProvisioningProfile?
    /// `Bundle.main.appStoreReceiptURL?.lastPathComponent`.
    var receiptName: @Sendable () -> String?
    /// The app's default keychain access group (`TEAMID.bundle.id`), or nil.
    var keychainAccessGroup: @Sendable () -> String?
    var bundleId: @Sendable () -> String?
    /// `CFBundleVersion`.
    var bundleVersion: @Sendable () -> String?
    /// `CFBundleShortVersionString`.
    var shortVersion: @Sendable () -> String?
    var osName: String
    var osVersion: @Sendable () -> String
    /// `kern.osversion` (`23F79`).
    var osBuild: @Sendable () -> String?
    /// The machine identifier (`iPhone17,1`).
    var machine: @Sendable () -> String
    /// `UIDevice.model` (`iPhone`).
    var deviceModel: @Sendable () async -> String
    /// Names of this process's threads.
    var threadNames: @Sendable () -> [String] = { [] }
    /// Whether an image path is in the dyld shared cache.
    var inSharedCache: @Sendable (String) -> Bool = { _ in true }
    /// The app bundle's path.
    var bundlePath: String = ""
    /// `cryptid` of the main executable's `LC_ENCRYPTION_INFO_64`; nil when unread.
    var mainImageEncrypted: @Sendable () -> Bool? = { nil }
    /// `get-task-allow` in the main executable's code signature; nil when there is no entitlements blob.
    var signedGetTaskAllow: @Sendable () throws -> Bool? = { nil }

    /// The readers of this process.
    static var live: IntegrityProbeInputs {
        IntegrityProbeInputs(
            fileExists: { LiveIntegrityReaders.fileExists($0) },
            canWriteOutsideSandbox: { try LiveIntegrityReaders.canWriteOutsideSandbox() },
            environment: { ProcessInfo.processInfo.environment },
            isSimulatorBuild: LiveIntegrityReaders.isSimulatorBuild,
            isDebugBuild: LiveIntegrityReaders.isDebugBuild,
            onMacHost: LiveIntegrityReaders.onMacHost,
            isTraced: { try LiveIntegrityReaders.isTraced() },
            loadedImages: { LiveIntegrityReaders.loadedImages() },
            localPortOpen: { LiveIntegrityReaders.localPortOpen($0) },
            provisioningProfile: { try LiveIntegrityReaders.provisioningProfile() },
            receiptName: { LiveIntegrityReaders.receiptName() },
            keychainAccessGroup: { LiveIntegrityReaders.keychainAccessGroup() },
            bundleId: { Bundle.main.bundleIdentifier },
            bundleVersion: { Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String },
            shortVersion: { Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String },
            osName: LiveIntegrityReaders.osName,
            osVersion: { DeviceInfo.osVersion },
            osBuild: { LiveIntegrityReaders.osBuild() },
            machine: { DeviceInfo.model },
            deviceModel: { await LiveIntegrityReaders.deviceModel() },
            threadNames: { LiveIntegrityReaders.threadNames() },
            inSharedCache: { LiveIntegrityReaders.inSharedCache($0) },
            bundlePath: LiveIntegrityReaders.appBundlePath,
            mainImageEncrypted: { LiveIntegrityReaders.mainImageEncrypted() },
            signedGetTaskAllow: { try LiveIntegrityReaders.signedGetTaskAllow() }
        )
    }
}

/// The live readers behind ``IntegrityProbeInputs/live``.
enum LiveIntegrityReaders {

    static var isSimulatorBuild: Bool {
        #if targetEnvironment(simulator)
        return true
        #else
        return false
        #endif
    }

    static var isDebugBuild: Bool {
        #if DEBUG
        return true
        #else
        return false
        #endif
    }

    static var onMacHost: Bool {
        #if os(macOS) || targetEnvironment(simulator) || targetEnvironment(macCatalyst)
        return true
        #else
        // An iPhone / iPad app running on an Apple silicon Mac sees the Mac's file system and libraries.
        return ProcessInfo.processInfo.isiOSAppOnMac || ProcessInfo.processInfo.isMacCatalystApp
        #endif
    }

    /// The app's own bundle: the containing app's for an app extension (`App.app/PlugIns/X.appex`),
    /// so the app's frameworks count as its own.
    static var appBundlePath: String {
        let path = Bundle.main.bundlePath
        guard path.hasSuffix(".appex") else { return path }
        let containing = ((path as NSString).deletingLastPathComponent as NSString).deletingLastPathComponent
        return containing.hasSuffix(".app") ? containing : path
    }

    static var osName: String {
        #if os(macOS)
        return "macOS"
        #else
        return "iOS"
        #endif
    }

    static func fileExists(_ path: String) -> Bool {
        // lstat: a symlink counts too (rootless jailbreaks link /var/jb).
        var info = stat()
        return lstat(path, &info) == 0
    }

    /// Writes (and removes) a file directly under `/private`: the sandbox of an
    /// iOS app (and the permissions of a Mac) refuse it, and so do rootless
    /// jailbreaks, which leave apps sandboxed; older, rootful ones do not.
    static func canWriteOutsideSandbox() throws -> Bool {
        let path = "/private/pinvault-jb-\(UUID().uuidString)"
        let fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0o600)
        guard fd >= 0 else { return false }
        _ = write(fd, "x", 1)
        close(fd)
        unlink(path)
        return true
    }

    /// `P_TRACED` in this process's `kinfo_proc` (sys/proc.h).
    static func isTraced() throws -> Bool {
        var info = kinfo_proc()
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        var size = MemoryLayout<kinfo_proc>.stride
        let result = mib.withUnsafeMutableBufferPointer { buffer in
            sysctl(buffer.baseAddress, u_int(buffer.count), &info, &size, nil, 0)
        }
        guard result == 0 else { throw ProbeReadError("sysctl(KERN_PROC_PID) failed: errno \(errno)") }
        return (info.kp_proc.p_flag & pTraced) != 0
    }

    private static let pTraced: Int32 = 0x0000_0800

    static func loadedImages() -> [String] {
        let count = min(_dyld_image_count(), 4096)
        var names: [String] = []
        names.reserveCapacity(Int(count))
        for index in 0..<count {
            if let name = _dyld_get_image_name(index) { names.append(String(cString: name)) }
        }
        return names
    }

    /// A non-blocking connect to `127.0.0.1:port`, at most 200 ms.
    static func localPortOpen(_ port: UInt16) -> Bool {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { return false }
        defer { close(fd) }
        var noSigPipe: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &noSigPipe, socklen_t(MemoryLayout<Int32>.size))
        let flags = fcntl(fd, F_GETFL, 0)
        _ = fcntl(fd, F_SETFL, flags | O_NONBLOCK)

        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = port.bigEndian
        address.sin_addr.s_addr = inet_addr("127.0.0.1")
        let connected = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        if connected == 0 { return true }
        guard errno == EINPROGRESS else { return false }
        var poller = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
        guard poll(&poller, 1, 200) == 1 else { return false }
        var socketError: Int32 = 0
        var length = socklen_t(MemoryLayout<Int32>.size)
        guard getsockopt(fd, SOL_SOCKET, SO_ERROR, &socketError, &length) == 0 else { return false }
        return socketError == 0
    }

    /// The receipt's file name, when the file is there: a path alone says nothing
    /// (`appStoreReceiptURL` names `receipt` for any app without a profile).
    static func receiptName() -> String? {
        guard let url = Bundle.main.appStoreReceiptURL, FileManager.default.fileExists(atPath: url.path) else { return nil }
        return url.lastPathComponent
    }

    /// The names of this process's threads (`pthread_getname_np` of each Mach thread).
    static func threadNames() -> [String] {
        var threads: thread_act_array_t?
        var count: mach_msg_type_number_t = 0
        guard task_threads(mach_task_self_, &threads, &count) == KERN_SUCCESS, let threads else { return [] }
        defer {
            for index in 0..<Int(count) { mach_port_deallocate(mach_task_self_, threads[index]) }
            vm_deallocate(mach_task_self_, vm_address_t(UInt(bitPattern: threads)), vm_size_t(Int(count) * MemoryLayout<thread_t>.stride))
        }
        var names: [String] = []
        for index in 0..<min(Int(count), 1024) {
            guard let pthread = pthread_from_mach_thread_np(threads[index]) else { continue }
            var buffer = [CChar](repeating: 0, count: 64)
            if pthread_getname_np(pthread, &buffer, buffer.count) == 0 {
                let name = String(decoding: buffer.prefix(while: { $0 != 0 }).map { UInt8(bitPattern: $0) }, as: UTF8.self)
                if !name.isEmpty { names.append(name) }
            }
        }
        return names
    }

    static func inSharedCache(_ path: String) -> Bool {
        if #available(iOS 15.0, macOS 12.0, *) {
            return _dyld_shared_cache_contains_path(path)
        }
        return true
    }

    /// `cryptid` of the main executable's `LC_ENCRYPTION_INFO_64`, read from its
    /// loaded header (the kernel decrypts the pages, not the header); nil when
    /// the executable has no such command or cannot be found.
    static func mainImageEncrypted() -> Bool? {
        // The main executable's own header: no path comparison that a symlinked
        // or relocated container path could make miss.
        guard let header = mainExecutableHeader() else { return nil }
        return MachOReader.cryptid(header: UnsafeRawPointer(header)).map { $0 != 0 }
    }

    /// The header of the main executable: the image dyld loaded as `MH_EXECUTE`.
    private static func mainExecutableHeader() -> UnsafePointer<mach_header>? {
        for index in 0..<_dyld_image_count() {
            guard let header = _dyld_get_image_header(index) else { continue }
            if header.pointee.filetype == UInt32(MH_EXECUTE) { return header }
        }
        return nil
    }

    /// `get-task-allow` in the code signature of the main executable on disk.
    static func signedGetTaskAllow() throws -> Bool? {
        guard let url = Bundle.main.executableURL else { return nil }
        guard let entitlements = try MachOReader.entitlements(of: url) else { return nil }
        return entitlements["get-task-allow"] as? Bool ?? false
    }

    static func provisioningProfile() throws -> ProvisioningProfile? {
        guard let url = Bundle.main.url(forResource: "embedded", withExtension: "mobileprovision") else { return nil }
        let data = try Data(contentsOf: url)
        guard let profile = ProvisioningProfile.parse(data) else {
            throw ProbeReadError("embedded.mobileprovision holds no readable property list")
        }
        return profile
    }

    /// The default keychain access group of this app (`AppIdentifierPrefix` +
    /// bundle id): a probe item is added, its access group read back, and the
    /// item removed. Read once per process. nil on macOS and where the
    /// keychain refuses (an unsigned build: errSecMissingEntitlement).
    static func keychainAccessGroup() -> String? {
        if let cached = accessGroupCache.get() { return cached }
        let group = readKeychainAccessGroup()
        accessGroupCache.set(.some(group))
        return group
    }

    private static let accessGroupCache = Locked<String??>(nil)

    private static func readKeychainAccessGroup() -> String? {
        #if os(iOS) || os(tvOS) || os(watchOS) || os(visionOS)
        let base: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: "io.github.umutcansu.pinvault.integrity",
            kSecAttrAccount: "team-id-probe",
        ]
        var query = base
        query[kSecReturnAttributes] = true
        query[kSecMatchLimit] = kSecMatchLimitOne
        var result: CFTypeRef?
        var status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound {
            var add = base
            add[kSecAttrAccessible] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            add[kSecValueData] = Data()
            add[kSecReturnAttributes] = true
            status = SecItemAdd(add as CFDictionary, &result)
        }
        defer { SecItemDelete(base as CFDictionary) }
        guard status == errSecSuccess, let attributes = result as? [CFString: Any] else { return nil }
        return attributes[kSecAttrAccessGroup] as? String
        #else
        return nil
        #endif
    }

    /// The OS build (`23F79`): the simulated runtime's on the simulator (whose
    /// kernel is the Mac's), `kern.osversion` elsewhere.
    static func osBuild() -> String? {
        #if targetEnvironment(simulator)
        if let build = ProcessInfo.processInfo.environment["SIMULATOR_RUNTIME_BUILD_VERSION"], !build.isEmpty { return build }
        #endif
        return sysctlString("kern.osversion")
    }

    static func sysctlString(_ name: String) -> String? {
        var size = 0
        guard sysctlbyname(name, nil, &size, nil, 0) == 0, size > 0 else { return nil }
        var buffer = [CChar](repeating: 0, count: size)
        guard sysctlbyname(name, &buffer, &size, nil, 0) == 0 else { return nil }
        let text = String(decoding: buffer.prefix(while: { $0 != 0 }).map { UInt8(bitPattern: $0) }, as: UTF8.self)
        return text.isEmpty ? nil : text
    }

    static func deviceModel() async -> String {
        #if canImport(UIKit) && !os(watchOS)
        return await MainActor.run { UIDevice.current.model }
        #else
        return "Mac"
        #endif
    }
}

/// A probe input that could not be read.
struct ProbeReadError: Error, CustomStringConvertible {
    let description: String

    init(_ description: String) {
        self.description = description
    }
}
