import Foundation
import os
import Security
import SwiftUI
import UIKit
import PinVault

// Küçük yardımcılar: kilitli kutu, log, saat damgası, hata metni, zaman aşımı,
// Keychain, cihaz bilgisi. Android'de bunların karşılıkları Java/Android API'leri.

/// NSLock arkasında bir değer; arka plan iş parçacıklarından okunup yazılır.
final class Guarded<Value>: @unchecked Sendable {
    private let lock = NSLock()
    private var value: Value

    init(_ value: Value) { self.value = value }

    func get() -> Value { lock.withLock { value } }

    @discardableResult
    func update<R>(_ body: (inout Value) -> R) -> R { lock.withLock { body(&value) } }
}

/// Uygulamanın log'u (Android: `Log.d(App.TAG, …)`, TAG = "PinVault"). sample-e2e
/// `log show` ile subsystem `com.example.sampleclient` satırlarını da okur.
/// Release'te d/i hiç yazılmaz (Android'de R8 siler, proguard-release.pro).
enum AppLog {
    static let subsystem = "com.example.sampleclient"
    private static let logger = Logger(subsystem: subsystem, category: "PinVault")

    static func d(_ message: String) {
        #if DIAGNOSTIC_LOGS
        logger.notice("\(message, privacy: .public)")
        #endif
    }

    static func w(_ message: String) {
        logger.notice("\(message, privacy: .public)")
    }

    static func e(_ message: String, _ error: (any Error)? = nil) {
        if let error {
            logger.error("\(message, privacy: .public): \(ErrorText.describe(error), privacy: .public)")
        } else {
            logger.error("\(message, privacy: .public)")
        }
    }
}

/// "HH:mm:ss" (Android: `SimpleDateFormat("HH:mm:ss", Locale.US)`).
enum Clock {
    static func hms(_ date: Date = Date()) -> String {
        let c = Calendar.current.dateComponents([.hour, .minute, .second], from: date)
        return String(format: "%02d:%02d:%02d", c.hour ?? 0, c.minute ?? 0, c.second ?? 0)
    }

    /// Epoch ms → "HH:mm:ss"; yoksa "?".
    static func hms(epochMs: Int64?) -> String {
        guard let epochMs else { return "?" }
        return hms(Date(timeIntervalSince1970: TimeInterval(epochMs) / 1000))
    }
}

/// Uygulamanın kendi hataları; adları Java'daki karşılıklarıyla aynı
/// (ekranlar `getSimpleName() + "\n" + getMessage()` biçiminde yazar).
enum SampleError: Error, Sendable {
    case illegalState(String)
    case unsupportedOperation(String)
    case illegalArgument(String)

    var exceptionName: String {
        switch self {
        case .illegalState: return "IllegalStateException"
        case .unsupportedOperation: return "UnsupportedOperationException"
        case .illegalArgument: return "IllegalArgumentException"
        }
    }

    var message: String {
        switch self {
        case .illegalState(let m), .unsupportedOperation(let m), .illegalArgument(let m): return m
        }
    }
}

extension SampleError: LocalizedError {
    var errorDescription: String? { message }
}

/// Bir hatanın ekrandaki adı ve mesajı (Android: `e.getClass().getSimpleName()` ve `e.getMessage()`).
enum ErrorText {
    static func name(_ error: any Error) -> String {
        if let e = error as? PinVaultError { return e.exceptionName }
        if let e = error as? SampleError { return e.exceptionName }
        if error is URLError { return "URLError" }
        if error is CancellationError { return "CancellationError" }
        return String(describing: type(of: error))
    }

    static func message(_ error: any Error) -> String {
        if let e = error as? PinVaultError { return e.message }
        if let e = error as? SampleError { return e.message }
        if let e = error as? URLError { return "\(e.localizedDescription) [\(e.code.rawValue)]" }
        return (error as NSError).localizedDescription
    }

    /// "Ad\nmesaj" — sonuç kutusundaki biçim.
    static func block(_ error: any Error) -> String {
        "\(name(error))\n\(message(error))"
    }

    static func describe(_ error: any Error) -> String {
        "\(name(error)): \(message(error))"
    }
}

/// `withTimeoutOrNull` karşılığı: [operation] [seconds] içinde bitmezse nil.
/// Zaman aşımında beklemeden döner; iş arka planda iptal edilir (kütüphane iptali
/// dinlemese de ekran takılmaz).
func withTimeout<T: Sendable>(_ seconds: Double, _ operation: @escaping @Sendable () async -> T) async -> T? {
    let once = Guarded<CheckedContinuation<T?, Never>?>(nil)
    func finish(_ value: T?) {
        let continuation = once.update { slot -> CheckedContinuation<T?, Never>? in
            defer { slot = nil }
            return slot
        }
        continuation?.resume(returning: value)
    }
    return await withCheckedContinuation { (continuation: CheckedContinuation<T?, Never>) in
        once.update { $0 = continuation }
        let work = Task { finish(await operation()) }
        Task {
            try? await Task.sleep(nanoseconds: UInt64(seconds * 1_000_000_000))
            work.cancel()
            finish(nil)
        }
    }
}

/// Uygulamanın Keychain kayıtları (generic password, ThisDeviceOnly). Android'de
/// bunların yerinde Android Keystore anahtarları var.
enum Keychain {
    static let service = "com.example.sampleclient"

    static func read(_ account: String) -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess else { return nil }
        return result as? Data
    }

    static func write(_ account: String, _ data: Data) throws {
        delete(account)
        let item: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            kSecValueData as String: data,
        ]
        let status = SecItemAdd(item as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw SampleError.illegalState("Keychain kaydı yazılamadı (\(account), OSStatus \(status))")
        }
    }

    @discardableResult
    static func delete(_ account: String) -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        return SecItemDelete(query as CFDictionary) == errSecSuccess
    }
}

/// Uygulamanın `Library/Application Support` dizini (Android'in `files/` karşılığı).
enum AppFiles {
    static var applicationSupport: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
    }

    /// Dosyanın üstünü sıfırlayıp siler (flash bellekte garanti değil, ama düz kopya kalmasın).
    static func wipe(_ url: URL) {
        guard FileManager.default.fileExists(atPath: url.path) else { return }
        if let handle = try? FileHandle(forWritingTo: url) {
            let size = (try? handle.seekToEnd()) ?? 0
            try? handle.seek(toOffset: 0)
            var left = size
            let zeros = Data(count: 4096)
            while left > 0 {
                let n = Int(min(UInt64(zeros.count), left))
                try? handle.write(contentsOf: zeros.prefix(n))
                left -= UInt64(n)
            }
            try? handle.synchronize()
            try? handle.close()
        } else {
            AppLog.w("Could not overwrite \(url.lastPathComponent)")
        }
        do {
            try FileManager.default.removeItem(at: url)
        } catch {
            AppLog.w("Could not delete \(url.lastPathComponent)")
        }
    }
}

/// Cihaz bilgisi: Android'in `Build.MANUFACTURER`, `Build.MODEL` ve ANDROID_ID karşılıkları.
enum DeviceInfo {
    /// Makine kimliği (`iPhone17,1`); simülatörde simüle edilen cihazınki.
    static let model: String = {
        if let simulated = ProcessInfo.processInfo.environment["SIMULATOR_MODEL_IDENTIFIER"], !simulated.isEmpty {
            return simulated
        }
        var info = utsname()
        uname(&info)
        let machine = withUnsafeBytes(of: &info.machine) { raw in
            String(decoding: raw.prefix(while: { $0 != 0 }), as: UTF8.self)
        }
        return machine.isEmpty ? "iPhone" : machine
    }()

    /// `Build.MANUFACTURER + " " + Build.MODEL` karşılığı.
    static var alias: String { "Apple \(model)" }

    /// PinVault'un bu cihaz için kullandığı kimlik (Android: ANDROID_ID): identifierForVendor,
    /// küçük harf. Vault token'ları ve cihaza özel şifreleme anahtarı bu kimliğe bağlanır.
    @MainActor
    static var deviceId: String {
        if let cached = cachedDeviceId.get() { return cached }
        let id = UIDevice.current.identifierForVendor?.uuidString.lowercased() ?? ""
        cachedDeviceId.update { $0 = id }
        return id
    }

    /// ``deviceId``, arka plan işlerinden (UIDevice yalnızca ana iş parçacığında okunur).
    static func deviceIdFromAnyThread() -> String {
        if let cached = cachedDeviceId.get() { return cached }
        if Thread.isMainThread { return MainActor.assumeIsolated { deviceId } }
        return DispatchQueue.main.sync { MainActor.assumeIsolated { deviceId } }
    }

    private static let cachedDeviceId = Guarded<String?>(nil)
}

extension View {
    /// iOS 16'daki `onChange(of:perform:)` ve iOS 17'deki iki parametreli sürüm için tek ad.
    @ViewBuilder
    func onValueChange<V: Equatable>(of value: V, _ action: @escaping (V) -> Void) -> some View {
        if #available(iOS 17.0, *) {
            onChange(of: value) { _, new in action(new) }
        } else {
            onChange(of: value, perform: action)
        }
    }
}
