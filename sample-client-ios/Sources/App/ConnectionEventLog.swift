import Foundation
import PinVault

/// `PinVaultConnectionEvent`'lerin uygulama içi halka tamponu; ana ekran canlı olay
/// listesi olarak gösterir.
///
/// Kütüphane listener'ı TLS el sıkışmasının dışında, bir arka plan görevinde çağırır.
/// Satırlar burada, geliş sırasıyla yazılır; ``observer`` ana iş parçacığına geçişten
/// sorumludur (ekran her seferinde ``snapshot()``'ı baştan çizer).
///
/// En yeni kayıt başta. Tampon ``maxEntries`` ile sınırlı.
final class ConnectionEventLog: Sendable {

    static let maxEntries = 50

    private let entries = Guarded<[String]>([])
    private let observerBox = Guarded<(@Sendable () -> Void)?>(nil)

    /// Her olaydan sonra çağrılır (herhangi bir iş parçacığından). nil ile ayrılır.
    var observer: (@Sendable () -> Void)? {
        get { observerBox.get() }
        set { observerBox.update { $0 = newValue } }
    }

    func onEvent(_ event: PinVaultConnectionEvent) {
        let time = Clock.hms()
        var line: String?

        switch event {
        case let .connection(hostname, success, pinVersion, _, _, actualPin, _):
            let host = hostname.isEmpty ? "?" : hostname
            let preview = actualPin.count > 12 ? String(actualPin.prefix(12)) + "…" : actualPin
            line = "\(time) [\(success ? "✓" : "✗ UYUŞMAZLIK")] \(host)  pin v\(pinVersion)  sha256/\(preview)"
        case let .configUpdate(status, newVersion, _, _, failureReason):
            let reason = failureReason.map { " — \($0)" } ?? ""
            line = "\(time) [config] \(status.rawValue) v\(newVersion)\(reason)"
        case let .clientCertRenewal(status, _, _, configApiId, _, _, _):
            // Yalnızca iptal: kullanıcının bilmesi gereken tek sertifika olayı.
            if status == .reenrollRequired {
                line = "\(time) [kimlik] \(configApiId) bu cihazın kaydını iptal etti: vault dosyaları ve token'lar silindi, yeniden kayıt gerekli"
            }
        case let .attestation(configApiId, status, arc, rejectionReasons, warnings, tokenExpiresAt, _, _, failureReason):
            // Her atestasyon turu: geçti (token'ın süresi), kaldı (ARC ve açıklanan
            // nedenler) ya da sunucuya ulaşılamadı.
            switch status {
            case .pass:
                let warn = warnings.isEmpty ? "" : "  uyarı: " + warnings.joined(separator: ",")
                line = "\(time) [atestasyon] \(configApiId) GEÇTİ  arc=\(arc ?? "null")  token→\(Clock.hms(epochMs: tokenExpiresAt))\(warn)"
            case .reject:
                let reasons = rejectionReasons.isEmpty ? "(sunucu açıklamıyor)" : rejectionReasons.joined(separator: ",")
                line = "\(time) [atestasyon] \(configApiId) KALDI  arc=\(arc ?? "null")  neden: \(reasons)"
            case .failed:
                line = "\(time) [atestasyon] \(configApiId) yapılamadı — \(failureReason ?? "?")"
            }
        }

        if let line {
            entries.update { list in
                list.insert(line, at: 0)
                if list.count > Self.maxEntries { list.removeLast(list.count - Self.maxEntries) }
            }
        }
        observer?()
    }

    func snapshot() -> [String] {
        entries.get()
    }

    func clear() {
        entries.update { $0.removeAll() }
        observer?()
    }
}
