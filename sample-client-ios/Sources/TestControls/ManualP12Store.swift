#if TEST_CONTROLS
import CryptoKit
import Foundation
import Security

/// Çözülmüş elle P12 kimliği: P12 paketi ve parolası.
struct ManualP12Identity: Sendable {
    let p12: Data
    let password: String
}

/// Elle yüklenen istemci sertifikası (P12), bir kez içe aktarılıp Keychain'deki bir
/// anahtarla şifrelenmiş olarak saklanır (Android: ManualP12Store, Keystore anahtarı).
///
/// 1. ``inboxFile`` veri kabına konur: `Library/Application Support/manual-client.p12`
///    (sample-e2e Android'in `files/manual-client.p12` yolunu buraya çevirir).
/// 2. "P12 içe aktar" kullanıcıdan parolayı ister; dosya o parolayla açılır (doğrulanır).
/// 3. Paket ve parolası, Keychain'de duran (ThisDeviceOnly: yedeğe ve başka cihaza
///    geçmez) rastgele bir AES-256 anahtarıyla AES-GCM ile şifrelenip ``sealedFile``'a
///    yazılır; düz dosyanın üstü sıfırlanıp silinir.
/// 4. Uygulama açılışta paketi çözüp `clientKeystore(bytes, password:)` ile mTLS
///    bloğuna verir.
///
/// iOS farkı: iOS'ta PKCS#12 yazan bir API yok; Android'deki gibi paketi rastgele bir
/// parolayla yeniden kurmak yerine özgün paket ve kullanıcının parolası birlikte
/// şifrelenir (ikisi de yalnızca şifreli pakette durur).
///
/// **Neyi korur, neyi korumaz.** Yalnızca diskteki kopyayı korur (yedek, cihaz taşıma,
/// dosyayı kopyalayıp başka telefonda açma). Uygulama paketi her açılışta çözdüğü için
/// jailbreak'li telefonda uygulama adına çalışan kod da anahtarı kullanıp özel anahtarı
/// alabilir. Gerçek bir üründe elle yüklenen sertifika kullanılmamalı, cihaz kayıt
/// olmalı: orada özel anahtar Secure Enclave'de üretilir ve hiç dosyaya düşmez.
enum ManualP12Store {

    /// Veri kabına konan düz P12; içe aktarınca silinir.
    static let inboxFile = "manual-client.p12"
    /// Keychain anahtarıyla şifrelenmiş paket (Library/Application Support altında).
    static let sealedFile = "manual-client.sealed"
    /// Keychain kaydı (generic password, ThisDeviceOnly).
    static let keyAccount = "sample_manual_p12"

    enum Failure: Error {
        /// Parola yanlış ya da dosya P12 değil.
        case wrongPassword(OSStatus)
    }

    static func hasInbox() -> Bool {
        FileManager.default.fileExists(atPath: inbox.path)
    }

    static func isImported() -> Bool {
        FileManager.default.fileExists(atPath: sealed.path)
    }

    /// ``inboxFile``'ı [password] ile açar, şifreli pakete çevirir ve düz dosyayı siler.
    /// Sertifikanın CN'ini döndürür.
    static func importFromInbox(password: String) throws -> String {
        let original = try Data(contentsOf: inbox)
        let cn = try commonName(p12: original, password: password)
        try writeSealed(seal(pack(password: password, p12: original)))
        AppFiles.wipe(inbox)
        return cn
    }

    /// Şifreli paketi çözer; yoksa ya da anahtar artık açmıyorsa nil.
    static func load() -> ManualP12Identity? {
        guard let data = try? Data(contentsOf: sealed) else { return nil }
        do {
            return try unpack(unseal(data))
        } catch {
            AppLog.w("Manual P12 could not be opened: \(ErrorText.describe(error))")
            return nil
        }
    }

    /// Şifreli paketi, varsa düz dosyayı ve Keychain anahtarını siler.
    static func clear() {
        AppFiles.wipe(sealed)
        AppFiles.wipe(inbox)
        Keychain.delete(keyAccount)
    }

    /// Kimliğin sertifikasının CN'i (ekranda göstermek için).
    static func commonName(_ identity: ManualP12Identity) throws -> String {
        try commonName(p12: identity.p12, password: identity.password)
    }

    // ── iç işler ─────────────────────────────────────────────────────────

    private static var inbox: URL { AppFiles.applicationSupport.appendingPathComponent(inboxFile) }
    private static var sealed: URL { AppFiles.applicationSupport.appendingPathComponent(sealedFile) }

    private static func commonName(p12: Data, password: String) throws -> String {
        var items: CFArray?
        let status = SecPKCS12Import(p12 as CFData, [kSecImportExportPassphrase as String: password] as CFDictionary, &items)
        guard status == errSecSuccess else { throw Failure.wrongPassword(status) }
        guard let first = (items as? [[String: Any]])?.first,
              let identityRef = first[kSecImportItemIdentity as String] else {
            throw SampleError.illegalArgument("P12 içinde özel anahtar ve sertifika yok")
        }
        // swiftlint:disable:next force_cast
        let identity = identityRef as! SecIdentity
        var certificate: SecCertificate?
        guard SecIdentityCopyCertificate(identity, &certificate) == errSecSuccess, let certificate else {
            throw SampleError.illegalArgument("P12 içinde özel anahtar ve sertifika yok")
        }
        var cn: CFString?
        if SecCertificateCopyCommonName(certificate, &cn) == errSecSuccess, let cn {
            return cn as String
        }
        return (SecCertificateCopySubjectSummary(certificate) as String?) ?? "?"
    }

    /// [UInt16 parola uzunluğu][parola][UInt32 P12 uzunluğu][P12] (big-endian, Android ile aynı).
    private static func pack(password: String, p12: Data) -> Data {
        let pass = Data(password.utf8)
        var out = Data()
        var passLength = UInt16(pass.count).bigEndian
        var p12Length = UInt32(p12.count).bigEndian
        out.append(Data(bytes: &passLength, count: 2))
        out.append(pass)
        out.append(Data(bytes: &p12Length, count: 4))
        out.append(p12)
        return out
    }

    private static func unpack(_ data: Data) throws -> ManualP12Identity {
        let bytes = [UInt8](data)
        guard bytes.count >= 2 else { throw SampleError.illegalState("Manual P12 package is truncated") }
        let passLength = Int(bytes[0]) << 8 | Int(bytes[1])
        guard bytes.count >= 2 + passLength + 4 else { throw SampleError.illegalState("Manual P12 package is truncated") }
        let pass = String(decoding: bytes[2 ..< 2 + passLength], as: UTF8.self)
        var at = 2 + passLength
        let p12Length = bytes[at ..< at + 4].reduce(0) { $0 << 8 | Int($1) }
        at += 4
        guard bytes.count >= at + p12Length else { throw SampleError.illegalState("Manual P12 package is truncated") }
        return ManualP12Identity(p12: Data(bytes[at ..< at + p12Length]), password: pass)
    }

    /// Keychain'deki AES-256 anahtarı; yoksa üretir.
    private static func key(create: Bool) throws -> SymmetricKey {
        if let existing = Keychain.read(keyAccount), existing.count == 32 {
            return SymmetricKey(data: existing)
        }
        guard create else { throw SampleError.illegalState("Keychain key is gone") }
        let fresh = SymmetricKey(size: .bits256)
        try Keychain.write(keyAccount, fresh.withUnsafeBytes { Data($0) })
        return fresh
    }

    /// iv (12) + şifreli gövde + etiket (16): Android'deki düzen.
    private static func seal(_ plain: Data) throws -> Data {
        let box = try AES.GCM.seal(plain, using: key(create: true))
        guard let combined = box.combined else { throw SampleError.illegalState("AES-GCM output missing") }
        return combined
    }

    private static func unseal(_ sealed: Data) throws -> Data {
        try AES.GCM.open(AES.GCM.SealedBox(combined: sealed), using: key(create: false))
    }

    private static func writeSealed(_ bytes: Data) throws {
        let directory = AppFiles.applicationSupport
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        try bytes.write(to: sealed, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
        // Yedeğe ve cihaz taşımaya girmez (Android: sample_data_extraction_rules.xml).
        var url = sealed
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try? url.setResourceValues(values)
    }
}
#endif
