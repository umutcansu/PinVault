import Foundation
import PinVault

/// PinVault'un `CertificateConfigApi` arayüzünü uygulayan, HTTP yapmayan bir kaynak:
/// pin'ler derlemeye gömülü (`SampleHostConfig.targetPins`) ve sürüm sabit 1'dir.
/// Kütüphane bu API'yi kullandığında kendi HTTP istemcisini hiç çalıştırmaz. Yalnızca
/// test derlemelerinde seçilebilen "gömülü API" modunda kullanılır.
///
/// ## Ne doğrulanır, ne doğrulanmaz
///
/// - **İmza DOĞRULANMAZ.** ``fetchConfig(currentVersion:)`` hazır, ayrıştırılmış bir
///   `CertificateConfig` döndürür; ortada kütüphanenin doğrulayabileceği imzalı bir zarf
///   yoktur. Bu yüzden bu API'yi kullanan blok `allowUnsigned()` ile kurulur (bkz.
///   `AppModel.startEmbeddedApi`): imza, `issuedAt`/`expiresAt`, tekrar oynatma ve
///   sürüm düşürme kontrolleri YOKTUR, saklanan config'in de bütünlük kontrolü yoktur.
/// - Kütüphane yine de her config'te host adlarının ve pin'lerin biçimini denetler (en
///   az iki farklı pin, geçerli Base64) ve pin'leri her bağlantıda uygular.
/// - Burada bu kabul edilebilir, çünkü pin'ler uygulamanın içinden geliyor: güven
///   uygulamanın kendisine, yani imzasına dayanıyor.
///
/// ## Pin'leri uzaktan getiren kendi backend'in için
///
/// Bu türü kopyalayıp `fetchConfig` içinde bir remote-config SDK'sından ya da kendi
/// API'nden pin okumak YANLIŞTIR: o kaynağa yazabilen biri kendi pin'ini yayınlar ve
/// bütün trafiği dinler. Doğrusu: backend config'i imzalı zarf olarak versin, API türün
/// `SignedConfigSource`'u da uygulasın ve zarfı aynen kütüphaneye versin, blok
/// `signaturePublicKey(...)` taşısın, `allowUnsigned()` çağrılmasın. İmza anahtarı olan
/// bir blok, `SignedConfigSource` uygulamayan özel bir API ile `allowUnsigned()`
/// çağrılmadan kurulursa `PinVault.start` hata verir.
struct EmbeddedConfigApi: CertificateConfigApi {
    static let version = 1

    let hostname: String
    let pins: [String]

    func healthCheck() async throws -> Bool { true }

    func fetchConfig(currentVersion: Int) async throws -> CertificateConfig {
        CertificateConfig(
            version: Self.version,
            pins: [HostPin(hostname: hostname, sha256: pins, version: Self.version)]
        )
    }

    func downloadHostClientCert(hostname: String) async throws -> Data {
        throw SampleError.unsupportedOperation("Gömülü API host'a özel istemci sertifikası sunmaz")
    }

    func downloadVaultFile(endpoint: String) async throws -> Data {
        throw SampleError.unsupportedOperation("Gömülü API vault dosyası sunmaz")
    }

    func enroll(token: String?, deviceId: String?, deviceAlias: String?, deviceUid: String?) async throws -> EnrollmentResult {
        throw SampleError.unsupportedOperation("Gömülü API kayıt desteklemez")
    }
}
