import Foundation

/// Vault erişim token'ları. Yalnızca bellekte tutulur ve uygulama kapanınca silinir;
/// diske yazılmaz. PinVault token'ı her indirmede `accessToken { … }` sağlayıcısı
/// üzerinden buradan okur.
///
/// Sunucu cihazın kimliğini iptal ettiğinde (`REENROLL_REQUIRED`) ``AppModel`` hepsini
/// siler: iptal edilmiş bir cihazın elinde kullanılabilir token kalmasın.
enum VaultTokens {
    private static let tokens = Guarded<[String: String]>([:])

    static func put(_ key: String, _ token: String) {
        tokens.update { $0[key] = token.isEmpty ? nil : token }
    }

    /// Token yoksa boş dizi; sunucu bunu geçersiz token olarak reddeder.
    static func get(_ key: String) -> String {
        tokens.get()[key] ?? ""
    }

    /// Bütün token'ları unutur; kaç tane olduğunu döndürür.
    @discardableResult
    static func clear() -> Int {
        tokens.update { all in
            defer { all.removeAll() }
            return all.count
        }
    }
}
