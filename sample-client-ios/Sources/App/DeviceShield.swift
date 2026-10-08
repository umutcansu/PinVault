import Darwin
import Foundation
import MachO
import PinVault

/// Uygulamanın kendi ortam kontrolü (Android: DeviceShield.java), kütüphanenin
/// `environmentGuard`'ına verilir. `start` hep geçer (pinli trafik çalışmaya devam
/// etsin, sunucu atestasyonla kendi kararını versin); kayıt, dosya indirme, dosya
/// açma ve saklı dosyayı okuma, jailbreak / debugger / hooking izi olan cihazda
/// reddedilir.
///
/// Bu bir hız kesicidir: cihazı yöneten biri uygulama içindeki her kontrolü
/// kapatabilir. Asıl karar sunucunundur (App Attest + atestasyon politikası).
///
/// Release'te hep açık. Test derlemelerinde (Debug / E2E) Ayarlar'daki "Ortam
/// kontrolü" açılmadıkça kapalı: senaryolar simülatörde, hata ayıklayıcıyla koşar.
enum DeviceShield {

    static func allows(_ operation: GuardedOperation) -> Bool {
        if operation == .start { return true }
        if !enabled { return true }
        return !isCompromised()
    }

    static var enabled: Bool {
        #if TEST_CONTROLS
        return UserDefaults.standard.bool(forKey: "sample.environmentGuard")
        #else
        return true
        #endif
    }

    /// Hata ayıklayıcı her seferinde; dosya ve imaj taraması 30 saniyede bir.
    static func isCompromised() -> Bool {
        if traced() { return true }
        let now = Date().timeIntervalSince1970
        if let cached = cache.withLock({ $0 }), now - cached.at < 30 { return cached.verdict }
        let verdict = jailbroken() || hooked()
        cache.withLock { $0 = (now, verdict) }
        return verdict
    }

    private static let cache = Locked<(at: TimeInterval, verdict: Bool)?>(nil)

    private static func traced() -> Bool {
        var info = kinfo_proc()
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        var size = MemoryLayout<kinfo_proc>.stride
        guard sysctl(&mib, u_int(mib.count), &info, &size, nil, 0) == 0 else { return false }
        return (info.kp_proc.p_flag & 0x0000_0800) != 0
    }

    private static func jailbroken() -> Bool {
        #if targetEnvironment(simulator)
        return false
        #else
        let paths = [
            "/Applications/Cydia.app", "/Applications/Sileo.app", "/Applications/Zebra.app",
            "/var/jb", "/var/binpack", "/Library/MobileSubstrate/MobileSubstrate.dylib", "/.bootstrapped",
        ]
        var info = stat()
        return paths.contains { lstat($0, &info) == 0 }
        #endif
    }

    private static func hooked() -> Bool {
        if let inserted = ProcessInfo.processInfo.environment["DYLD_INSERT_LIBRARIES"], !inserted.isEmpty { return true }
        let markers = ["frida", "substrate", "substitute", "libhooker", "ellekit", "tweakinject", "sslkillswitch"]
        for index in 0..<_dyld_image_count() {
            guard let raw = _dyld_get_image_name(index) else { continue }
            let path = String(cString: raw)
            if path.hasPrefix("/var/jb/") || path.contains("/MobileSubstrate/") { return true }
            let name = (path.split(separator: "/").last.map(String.init) ?? path).lowercased()
            if markers.contains(where: { name.contains($0) }) { return true }
        }
        return false
    }
}

/// Küçük bir kilitli kutu (kütüphanenin `Locked`'ı dışarıya açık değil).
final class Locked<Value>: @unchecked Sendable {
    private var value: Value
    private let lock = NSLock()

    init(_ value: Value) { self.value = value }

    func withLock<Result>(_ body: (inout Value) -> Result) -> Result {
        lock.lock()
        defer { lock.unlock() }
        return body(&value)
    }
}
