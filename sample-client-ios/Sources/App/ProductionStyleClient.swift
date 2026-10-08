import Foundation

// Bu dosya PinVault'u import ETMEZ (bkz. ProductionStyleClient).

/// ``ProductionStyleClient``'ın istek attığı nesne. Uygulama katmanı PinVault'un
/// `PinnedSession`'ını verir (AppModel.swift'te bu protokole uyar).
protocol ProductionStyleTransport: AnyObject, Sendable {
    func data(for request: URLRequest) async throws -> (Data, URLResponse)
}

/// Senin gerçek uygulamandaki **SoftPOSService** network katmanının minimal aynası.
/// Önemli kural: bu tür *PinVault import etmez* — kendi `URLSessionConfiguration`'ını
/// kurar, pinlemeyi dışarıdan verilen bir ``PinningInstaller`` takar. PinVault
/// entegrasyonu uygulama katmanında (``AppModel``) yapılır: AppModel buraya
/// `PinVault.shared.applyTo`'yu verir.
///
/// Neden pin listesini kopyalayan kendi doğrulaması değil? Hazır "SSL pinning bypass"
/// betikleri tek tek uygulamaların kendi doğrulama kodunu hedefler; pin kontrolü
/// yalnızca el sıkışmada çalışır ve `requireCaTrust` gibi kütüphane korumaları ona
/// ulaşmaz. PinVault'un oturumu her el sıkışmada güncel config'i okur ve pin değişince
/// kendini yeniden kurar. "PinVault'u import etmeyen network katmanı" deseni korunur,
/// pinleme mekanizması kütüphaneninki olur.
///
/// - ``initialize(_:)``: pinlemeyi takan geri çağrıyla client'ı bir kez kurar.
///   `applyTo` pin-kurtarma adımını da takar: pin uyuşmazlığında config tazelenir ve
///   istek bir kez yinelenir, burada ayrıca bir retry mantığı gerekmez.
/// - ``updatePins()``: yeni config geldiğinde çağrılır. Kütüphanenin oturumu yeni
///   pinlerle kendini yeniden kurduğu için yapılacak bir şey kalmaz (Android'de açık
///   bağlantılar burada boşaltılıyordu).
///
/// Mock host adları (`mock-tls.sample` …) Android'de bu client'ın `MockDns`'iyle
/// çözülüyordu; iOS'ta PinVault config'indeki `resolve(host:to:)` aynı işi görür.
enum ProductionStyleClient {

    /// Bir `URLSessionConfiguration`'a pinleme takıp istek atacak nesneyi döndüren geri
    /// çağrı. Uygulama katmanı `PinVault.shared.applyTo` verir; bu tür PinVault'u tanımaz.
    typealias PinningInstaller = @Sendable (URLSessionConfiguration) -> any ProductionStyleTransport

    private static let installer = Guarded<PinningInstaller?>(nil)
    private static let client = Guarded<(any ProductionStyleTransport)?>(nil)

    static func initialize(_ pinning: @escaping PinningInstaller) {
        installer.update { $0 = pinning }
        rebuild()
        AppLog.d("ProdStyleClient: initialized — pinning installed by the app layer")
    }

    /// Yeni bir pin config'i uygulandı. Oturum pinleri canlı okur ve kütüphane onu
    /// pin değişince yeniden kurar; havuzdaki bağlantılar yeni pinlerle el sıkışır.
    static func updatePins() {
        guard client.get() != nil else { return }
        AppLog.d("ProdStyleClient: pins updated — the live client follows the new config")
    }

    private static func rebuild() {
        guard let pinning = installer.get() else { return }
        let configuration = URLSessionConfiguration.ephemeral
        // OkHttp'nin varsayılanları gibi 10 sn.
        configuration.timeoutIntervalForRequest = 10
        configuration.timeoutIntervalForResource = 30
        let fresh = pinning(configuration)
        client.update { $0 = fresh }
    }

    static func execute(_ request: URLRequest) async throws -> (Data, URLResponse) {
        guard let c = client.get() else { throw SampleError.illegalState("ProductionStyleClient not initialized") }
        return try await c.data(for: request)
    }
}
