#if TEST_CONTROLS
import CryptoKit
import LocalAuthentication
import Security
import SwiftUI
import PinVault

/// Depolama (yalnızca test derlemeleri; Android: StorageActivity): PinVault'un bu cihazda
/// ne sakladığını ve nasıl sakladığını gösterir. Uygulama yalnızca kendi dosyalarını
/// okur; hiçbir şeyi çözmez.
///
/// - Şifreli tercih dosyaları (`Library/Application Support/pinvault/pinvault_secure_*.plist`;
///   değerler AES-256-GCM, kayıt adları HMAC, ikisinin anahtarı da Keychain'de): kayıt
///   adlarının ve değerlerin okunamadığı, host adı / pin gibi düz metinlerin dosyada
///   geçmediği gösterilir.
/// - Vault dosya deposu (`…/pinvault/vault_files/*.enc`): boyut ve başlık.
/// - Keychain kayıtları: anahtar türü, boyut, Secure Enclave, erişim sınıfı.
/// - İstemci sertifikası kaydı: ham değerin PKCS12 olarak açılamadığı.
struct StorageView: View {
    @ObservedObject private var model = AppModel.shared
    @State private var text = S.storageLoading

    var body: some View {
        ScreenBody {
            ActionButton(id: "refreshStorageButton", title: S.storageRefresh) { render() }
            StatusText(id: "storageView", text: text)
        }
        .screenChrome(S.storageTitle)
        .onAppear { render() }
    }

    private func render() {
        text = S.storageLoading
        let mode = model.activeMode.label
        let ready = model.initState.phase == .ready
        Task {
            let result = await Task.detached(priority: .userInitiated) {
                StorageReport.describe(modeLabel: mode, initialized: ready)
            }.value
            text = result
        }
    }
}

/// Depolama dökümü (arka planda üretilir).
enum StorageReport {
    /// PinVault 2.0.x'in dosyaları (Android'de ilk açılışta taşınır; iOS'ta hiç olmadı).
    private static let legacyFiles = ["pinvault_client_cert.plist", "pinvault_signing_keys.plist", "pinvault_vault_files.plist"]
    /// Kütüphanenin kayıt adları; şifreli dosyada hiçbiri okunur olmamalı.
    private static let plainKeyNames = ["config_", "client_p12_", "vault_data_", "vault_ver_", "keyset_"]

    private static var pinvaultDir: URL { AppFiles.applicationSupport.appendingPathComponent("pinvault") }

    static func describe(modeLabel: String, initialized: Bool) -> String {
        var out = ""
        out += "Mod: \(modeLabel)\n"
        out += "forceUpdate (kalıcı): \(initialized ? (PinVault.shared.isForceUpdate() ? "açık" : "kapalı") : "(PinVault başlatılmadı)")\n\n"

        // iOS: Keychain (Android: Android Keystore); dosyalar Library/Application Support/pinvault/*.plist.
        out += "== Şifreli tercih dosyaları (AES-256-GCM, anahtarlar Keychain'de) ==\n"
        let files = ((try? FileManager.default.contentsOfDirectory(atPath: pinvaultDir.path)) ?? [])
            .filter { $0.hasSuffix(".plist") && ($0.hasPrefix("ssl_cert_config") || $0.hasPrefix("pinvault_")) }
            .sorted()
        for name in files {
            let url = pinvaultDir.appendingPathComponent(name)
            let raw = (try? Data(contentsOf: url)) ?? Data()
            let dict = (try? PropertyListSerialization.propertyList(from: raw, format: nil)) as? [String: Any] ?? [:]
            if name == "pinvault_vault_file_versions.plist" {
                let table = dict.keys.sorted().map { "\($0)=\(text(dict[$0]))" }.joined(separator: ", ")
                out += "• \(name) — \(raw.count) B, düz sürüm tablosu: \(table.isEmpty ? "(boş)" : table)\n"
                continue
            }
            let entries = dict.keys.sorted().map { ($0, text(dict[$0])) }
            let legacy = name.hasPrefix("ssl_cert_config") || legacyFiles.contains(name)
            out += "• \(name) — \(raw.count) B, \(entries.count) kayıt\(legacy ? " (PinVault 2.0.x dosyası, ilk açılışta taşınır)" : "")\n"
            if !legacy {
                out += "   kayıt adları okunabilir mi: \(plainNames(entries) ? "EVET ✗" : "hayır ✓ (HMAC)")\n"
            }
            if let first = entries.first {
                out += "   örnek: \(shorten(first.0)) → \(shorten(first.1))\n"
            }
            out += "   düz metin sızıntısı (host adı, IP, pin): \(leaks(raw, dict) ? "VAR ✗" : "yok ✓")\n"
        }
        if files.isEmpty { out += "(PinVault tercih dosyası yok)\n" }

        // iOS: Library/Application Support/pinvault/vault_files (Android: files/vault_files).
        out += "\n== Vault dosya deposu (Library/Application Support/pinvault/vault_files, AES-256-GCM, Keychain anahtarı) ==\n"
        let vaultDir = pinvaultDir.appendingPathComponent("vault_files")
        let vaultFiles = ((try? FileManager.default.contentsOfDirectory(atPath: vaultDir.path)) ?? []).sorted()
        if vaultFiles.isEmpty {
            out += "(dosya yok)\n"
        } else {
            for name in vaultFiles {
                let head = [UInt8]((try? Data(contentsOf: vaultDir.appendingPathComponent(name))) ?? Data())
                // Güncel biçim: "PVF2" [sürüm, 4 bayt] [iv_len, 1] [iv] [şifreli gövde + etiket];
                // ad ve sürüm GCM etiketinin kapsadığı ek veride. Eski biçimde başlık yalnızca [iv_len][iv].
                let pvf2 = head.count >= 9 && head[0] == 0x50 && head[1] == 0x56 && head[2] == 0x46 && head[3] == 0x32
                let ivAt = pvf2 ? 9 : 1
                let ivLength = head.count >= ivAt ? Int(head[ivAt - 1]) : 0
                out += "• \(name) — \(head.count) B, başlık: "
                if pvf2 {
                    let version = Int(head[4]) << 24 | Int(head[5]) << 16 | Int(head[6]) << 8 | Int(head[7])
                    out += "PVF2 [sürüm=\(version)] "
                } else {
                    out += "(eski biçim) "
                }
                out += "[iv_len=\(ivLength)] \(hex(head, from: ivAt, count: min(ivLength, 12))) …\n"
            }
        }

        out += "\n== İmza doğrulaması (PinVault.signingStatus) ==\n"
        out += signingDetail(initialized: initialized) + "\n"

        // iOS: Keychain (Android: "== Android Keystore =="; aynı satır biçimi).
        out += "\n== Keychain ==\n"
        let keychain = keychainLines()
        out += keychain.isEmpty ? "(PinVault anahtarı yok)\n" : keychain.map { "• \($0)\n" }.joined()

        out += "\n== İstemci sertifikası (pinvault_secure_client_cert) ==\n"
        if !PinVault.shared.isEnrolled() {
            out += "kayıtlı değil\n"
        } else {
            out += "kayıtlı — CN=\(PinVault.shared.enrolledClientCN() ?? "?")\n"
            out += "kimlik anahtarının yeri (PinVault.identityKeySecurityLevel): \(PinVault.shared.identityKeySecurityLevel()?.wireName ?? "yok")\n"
            let certPrefs = pinvaultDir.appendingPathComponent("pinvault_secure_client_cert.plist")
            if let raw = try? Data(contentsOf: certPrefs) {
                let dict = (try? PropertyListSerialization.propertyList(from: raw, format: nil)) as? [String: Any] ?? [:]
                out += "ham kayıt PKCS12 olarak açılıyor mu: \(rawRecordOpensAsP12(dict) ? "EVET ✗ (şifresiz!)" : "hayır ✓ (şifreli)")\n"
            }
        }
        // Elle yüklenen P12 yalnızca Keychain anahtarıyla şifreli kopyasıyla durur; veri
        // kabına konan düz dosya içe aktarınca silinir (ManualP12Store).
        let sealed = AppFiles.applicationSupport.appendingPathComponent(ManualP12Store.sealedFile)
        let inbox = AppFiles.applicationSupport.appendingPathComponent(ManualP12Store.inboxFile)
        let sealedSize = (try? FileManager.default.attributesOfItem(atPath: sealed.path)[.size] as? NSNumber)?.intValue
        out += "elle yüklenen P12: \(sealedSize.map { "şifreli kopya \($0) B (Keychain anahtarıyla)" } ?? "yok")"
        out += AppSettings.useManualP12() ? " (kullanılıyor)\n" : "\n"
        let inboxPresent = FileManager.default.fileExists(atPath: inbox.path)
        out += "düz P12 dosyası (Library/Application Support/\(ManualP12Store.inboxFile)): "
        out += inboxPresent ? "VAR ✗ — içe aktarılmayı bekliyor\n" : "yok ✓\n"
        return out
    }

    /// Tam anahtar kimlikleri: uygulanan anahtar seti ve iptal edilen anahtarlar burada görünür.
    private static func signingDetail(initialized: Bool) -> String {
        guard let st = PinVault.shared.signingStatus() else {
            return initialized ? "(imza doğrulaması yok)" : "(PinVault başlatılmadı)"
        }
        var sb = "gereken imza: \(st.requiredSignatures), anahtar seti: v\(st.keySetVersion)"
        // iOS: "uygulamaya gömülü" (Android: "APK'ya gömülü").
        sb += st.keySetVersion == 0 ? " (uygulamaya gömülü anahtarlar)\n" : " (sunucudan gelen, kurtarma anahtarıyla imzalı)\n"
        sb += "güvenilen anahtarlar:\n"
        for id in st.trustedKeyIds { sb += "  • \(id)\n" }
        sb += "kurtarma anahtarları: \(st.recoveryKeyIds.isEmpty ? "yok\n" : "\n")"
        for id in st.recoveryKeyIds { sb += "  • \(id)\n" }
        sb += "son config'i imzalayan: "
        sb += st.lastConfigSignedBy.isEmpty ? "—" : st.lastConfigSignedBy.joined(separator: ", ")
        return sb
    }

    // MARK: Tercih dosyaları

    private static func text(_ value: Any?) -> String {
        switch value {
        case let string as String: return string
        case let data as Data: return data.base64EncodedString()
        case let number as NSNumber: return number.stringValue
        case nil: return ""
        default: return String(describing: value!)
        }
    }

    private static func plainNames(_ entries: [(String, String)]) -> Bool {
        entries.contains { entry in plainKeyNames.contains { entry.0.contains($0) } }
    }

    /// Ham dosyada ya da XML'e çevrilmiş halinde düz host adı, IP, pin ya da PEM var mı.
    private static func leaks(_ raw: Data, _ dict: [String: Any]) -> Bool {
        var haystack = String(decoding: raw, as: UTF8.self)
        if let xml = try? PropertyListSerialization.data(fromPropertyList: dict, format: .xml, options: 0) {
            haystack += String(decoding: xml, as: UTF8.self)
        }
        let needles = [
            Endpoints.targetHost, Endpoints.hostIp,
            SampleHostConfig.hostBootstrapPinPrimary, SampleHostConfig.hostBootstrapPinBackup,
            "BEGIN", "sha256/",
        ]
        return needles.contains { !$0.isEmpty && haystack.contains($0) }
    }

    /// Saldırganın ilk deneyeceği parola: eski varsayılan "changeit".
    private static func rawRecordOpensAsP12(_ dict: [String: Any]) -> Bool {
        for value in dict.values {
            let raw: Data?
            switch value {
            case let data as Data: raw = data
            case let string as String: raw = Data(base64Encoded: string)
            default: raw = nil
            }
            guard let raw, !raw.isEmpty else { continue }
            var items: CFArray?
            let status = SecPKCS12Import(raw as CFData, [kSecImportExportPassphrase as String: "changeit"] as CFDictionary, &items)
            if status == errSecSuccess, let list = items as? [Any], !list.isEmpty { return true }
        }
        return false
    }

    // MARK: Keychain

    /// Uygulamanın Keychain'indeki PinVault ve örnek kayıtları (Android: Keystore takma adları).
    private static func keychainLines() -> [String] {
        var lines: [(String, String)] = []
        let context = LAContext()
        context.interactionNotAllowed = true

        // Anahtarlar (Secure Enclave / yazılım EC, RSA).
        let keyQuery: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecReturnAttributes as String: true,
            kSecReturnRef as String: true,
            kSecUseAuthenticationContext as String: context,
        ]
        var keyResult: CFTypeRef?
        if SecItemCopyMatching(keyQuery as CFDictionary, &keyResult) == errSecSuccess, let items = keyResult as? [[String: Any]] {
            var privateTags = Set<String>()
            for item in items where keyClass(item) == "private" { privateTags.insert(keyName(item)) }
            for item in items {
                let name = keyName(item)
                guard wanted(name) else { continue }
                let cls = keyClass(item)
                if cls == "public" && privateTags.contains(name) { continue }
                lines.append((name, describeKey(item, cls)))
            }
        }

        // Genel parolalar (tercih dosyalarının AES/HMAC anahtarları, vault dosya anahtarları, elle P12 anahtarı).
        let passwordQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecReturnAttributes as String: true,
            kSecUseAuthenticationContext as String: context,
        ]
        var passwordResult: CFTypeRef?
        if SecItemCopyMatching(passwordQuery as CFDictionary, &passwordResult) == errSecSuccess,
           let items = passwordResult as? [[String: Any]] {
            for item in items {
                let account = item[kSecAttrAccount as String] as? String ?? ""
                let service = item[kSecAttrService as String] as? String ?? ""
                let name = wanted(account) ? account : service
                guard wanted(name) else { continue }
                lines.append((name, "genel parola (Keychain), güvenli donanım: hayır, erişim: \(accessibility(item))"))
            }
        }
        return lines.sorted { $0.0 < $1.0 }.map { "\($0.0): \($0.1)" }
    }

    private static func wanted(_ name: String) -> Bool {
        name.hasPrefix("pinvault") || name.hasPrefix("sample_")
    }

    private static func keyName(_ item: [String: Any]) -> String {
        if let tag = item[kSecAttrApplicationTag as String] as? Data, !tag.isEmpty {
            return String(decoding: tag, as: UTF8.self)
        }
        return item[kSecAttrLabel as String] as? String ?? "?"
    }

    private static func keyClass(_ item: [String: Any]) -> String {
        let value = (item[kSecAttrKeyClass as String] as? String) ?? (item[kSecAttrKeyClass as String] as? NSNumber)?.stringValue
        if value == (kSecAttrKeyClassPrivate as String) { return "private" }
        if value == (kSecAttrKeyClassPublic as String) { return "public" }
        if value == (kSecAttrKeyClassSymmetric as String) { return "symmetric" }
        return "?"
    }

    private static func describeKey(_ item: [String: Any], _ cls: String) -> String {
        let type = (item[kSecAttrKeyType as String] as? String) ?? (item[kSecAttrKeyType as String] as? NSNumber)?.stringValue
        let algorithm = type == (kSecAttrKeyTypeRSA as String) ? "RSA"
            : type == (kSecAttrKeyTypeECSECPrimeRandom as String) ? "EC" : (type ?? "?")
        let bits = (item[kSecAttrKeySizeInBits as String] as? NSNumber)?.intValue ?? 0
        let secureEnclave = (item[kSecAttrTokenID as String] as? String) == (kSecAttrTokenIDSecureEnclave as String)
        var line = "\(algorithm) \(bits) bit"
        if cls == "public" { line += " (public key)" }
        line += ", güvenli donanım: \(secureEnclave ? "evet (Secure Enclave)" : "hayır")"
        if let ref = item[kSecValueRef as String], CFGetTypeID(ref as CFTypeRef) == SecKeyGetTypeID() {
            // swiftlint:disable:next force_cast
            let key = ref as! SecKey
            let publicKey = cls == "public" ? key : SecKeyCopyPublicKey(key)
            if let publicKey, let spki = spki(publicKey) {
                line += ", public key SHA-256: " + SHA256.hash(data: spki).map { String(format: "%02x", $0) }.joined()
            }
            // Özel anahtarın baytları istenir: Secure Enclave ve kSecAttrIsExtractable=false
            // anahtarlarında Keychain reddeder (OSStatus koduyla).
            if cls == "private" {
                var error: Unmanaged<CFError>?
                if SecKeyCopyExternalRepresentation(key, &error) != nil {
                    line += ", dışa aktarılabilir: EVET"
                } else {
                    let code = error.map { CFErrorGetCode($0.takeRetainedValue()) }.map(String.init) ?? "?"
                    line += ", dışa aktarılabilir: hayır (SecKeyCopyExternalRepresentation → \(code))"
                }
            }
        }
        line += ", erişim: \(accessibility(item))"
        return line
    }

    /// Erişim sınıfı. Erişim denetimiyle (SecAccessControl) üretilen anahtarlarda —
    /// Secure Enclave anahtarları — sınıfı denetim nesnesi taşır; Keychain'in
    /// `kSecAttrAccessible` alanı orada anlamlı değildir (Secure Enclave anahtarı "dk" gösterir).
    private static func accessibility(_ item: [String: Any]) -> String {
        if let ref = item[kSecAttrAccessControl as String], CFGetTypeID(ref as CFTypeRef) == SecAccessControlGetTypeID() {
            // "<SecAccessControlRef: cku;od(cpo(DeviceOwnerAuthentication));…>": ilk alan koruma sınıfı.
            let description = String(describing: ref)
            let code = description.range(of: #"SecAccessControlRef: ([a-z]+)"#, options: .regularExpression)
                .map { String(description[$0].dropFirst("SecAccessControlRef: ".count)) }
            return "\(code.flatMap { protectionNames[$0] } ?? code ?? "?") (SecAccessControl)"
        }
        let value = item[kSecAttrAccessible as String] as? String
        return value.flatMap { protectionNames[$0] } ?? (value ?? "?")
    }

    /// Keychain'in koruma sınıfı kodları (`kSecAttrAccessible…` sabitlerinin değerleri).
    private static let protectionNames: [String: String] = [
        kSecAttrAccessibleWhenUnlocked as String: "WhenUnlocked",
        kSecAttrAccessibleAfterFirstUnlock as String: "AfterFirstUnlock",
        kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly as String: "WhenPasscodeSetThisDeviceOnly",
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly as String: "WhenUnlockedThisDeviceOnly",
        kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly as String: "AfterFirstUnlockThisDeviceOnly",
    ]

    /// X.509 SubjectPublicKeyInfo (sunucunun kaydettiği public key'in DER'i).
    private static func spki(_ publicKey: SecKey) -> Data? {
        guard let external = SecKeyCopyExternalRepresentation(publicKey, nil) as Data?,
              let attributes = SecKeyCopyAttributes(publicKey) as? [String: Any] else { return nil }
        let type = attributes[kSecAttrKeyType as String] as? String
        let bits = (attributes[kSecAttrKeySizeInBits as String] as? NSNumber)?.intValue ?? 0
        let algorithm: [UInt8]
        if type == (kSecAttrKeyTypeRSA as String) {
            // rsaEncryption + NULL
            algorithm = [0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00]
        } else if type == (kSecAttrKeyTypeECSECPrimeRandom as String) {
            let ecPublicKey: [UInt8] = [0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01]
            let curve: [UInt8]
            switch bits {
            case 256: curve = [0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]
            case 384: curve = [0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22]
            case 521: curve = [0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23]
            default: return nil
            }
            algorithm = tlv(0x30, ecPublicKey + curve)
        } else {
            return nil
        }
        return Data(tlv(0x30, algorithm + tlv(0x03, [0x00] + [UInt8](external))))
    }

    private static func tlv(_ tag: UInt8, _ content: [UInt8]) -> [UInt8] {
        var length: [UInt8]
        if content.count < 0x80 {
            length = [UInt8(content.count)]
        } else {
            var bytes: [UInt8] = []
            var n = content.count
            while n > 0 {
                bytes.insert(UInt8(n & 0xFF), at: 0)
                n >>= 8
            }
            length = [0x80 | UInt8(bytes.count)] + bytes
        }
        return [tag] + length + content
    }

    // MARK: Biçim

    private static func hex(_ data: [UInt8], from offset: Int, count: Int) -> String {
        guard offset < data.count, count > 0 else { return "" }
        return data[offset ..< min(data.count, offset + count)].map { String(format: "%02x", $0) }.joined()
    }

    private static func shorten(_ s: String) -> String {
        s.count > 18 ? String(s.prefix(18)) + "…" : s
    }
}
#endif
