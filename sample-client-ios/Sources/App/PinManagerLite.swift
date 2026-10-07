import Foundation
import PinVault

/// Gerçek uygulamadaki `PinManager`'ın sample karşılığı. Android'de PinVault'un
/// suspend API'lerini Java'dan senkron çağırmaya yarıyordu; burada zaman aşımlarını
/// (`withTimeoutOrNull`) ve "başlatılmadıysa" durumlarını aynı yerde tutar.
/// Hepsi arka planda çağrılır.
enum PinManagerLite {

    /// `PinVault.updateNow()`; zaman aşımında nil. Başlatılmadıysa `.failed`.
    static func updateNow(timeout seconds: Double = 10) async -> UpdateResult? {
        await withTimeout(seconds) { await PinVault.shared.updateNow() }
    }

    /// `enrollForResult`: token ile istemci sertifikası alır, doğrular, şifreli saklar
    /// ve pinli oturuma yükler. Olmazsa nedenini döndürür.
    static func enroll(token: String) async -> ClientCertEnrollmentResult {
        await PinVault.shared.enrollForResult(token: token)
    }

    /// Kayıt kodu onay bekliyorsa yönetici onayladı mı diye bir kez sorar.
    static func checkPending() async -> ClientCertEnrollmentResult {
        await PinVault.shared.checkPendingEnrollment()
    }

    /// Raporu şimdi gönderir; süre dolarsa nil.
    static func attestNow(timeout seconds: Double = 20) async -> AttestationStatus? {
        await withTimeout(seconds) { await PinVault.shared.attestNow() }
    }

    /// Elde geçerli bir token varsa onu, yoksa yeni bir turun sonucunu döndürür.
    static func fetchToken(host: String? = nil, timeout seconds: Double = 20) async -> AttestationTokenResult? {
        await withTimeout(seconds) { await PinVault.shared.fetchAttestationToken(host: host) }
    }

    /// Son atestasyon durumu, ağ yok; PinVault başlatılmamışsa nil
    /// (Android'de `IllegalStateException`).
    static func attestationStatusOrNull() -> AttestationStatus? {
        let status = PinVault.shared.attestationStatus()
        if status.result == .failed, status.lastError == "PinVault not initialized" { return nil }
        return status
    }

    static func fetchFile(_ key: String) async -> VaultFileResult {
        await PinVault.shared.fetchFile(key)
    }

    /// Yalnızca `updateWithPins` açık dosyalar çekilir. Anahtar → sonuç.
    static func syncAll() async -> [String: VaultFileResult] {
        await PinVault.shared.syncAllFiles()
    }

    /// Planlı işler (BGTaskScheduler ya da kütüphanenin uygulama içi zamanlayıcısı).
    static func scheduledWork(timeout seconds: Double = 5) async -> [ScheduledTaskInfo] {
        await withTimeout(seconds) { await PinVault.shared.scheduledTasks() } ?? []
    }

    /// Sunucusuz (statik) yapılandırma: pin'ler uygulamaya gömülü, hiçbir sunucuya
    /// bağlanılmaz. [requireCaTrust] açıksa host'un sertifikası pin'e ek olarak sistemin
    /// CA'larından da geçmeli. [resolve]: Android'deki MockDns'in karşılığı.
    static func staticConfig(
        hostPattern: String,
        pins: [String],
        requireCaTrust: Bool,
        resolve: [String: String] = [:]
    ) throws -> PinVaultConfig {
        let builder = PinVaultConfig.Builder()
            .staticPins(CertificateConfig(pins: [HostPin(hostname: hostPattern, sha256: pins)], forceUpdate: false))
        if requireCaTrust { builder.requireCaTrust(hostPattern) }
        for (host, address) in resolve.sorted(by: { $0.key < $1.key }) { builder.resolve(host: host, to: address) }
        return try builder.build()
    }

    /// Config'i hemen tazeler. Yeni bir config uygulandıysa true.
    static func refreshNow(timeout seconds: Double = 5) async -> Bool {
        switch await updateNow(timeout: seconds) {
        case .updated(let version):
            AppLog.d("PinManagerLite: refresh OK → updated to v\(version)")
            await MainActor.run { AppModel.bridgePinsToProductionStyleClient() }
            return true
        case .alreadyCurrent:
            AppLog.d("PinManagerLite: refresh OK → server returned the same version")
            return false
        case .failed(let reason, _):
            AppLog.w("PinManagerLite: refresh failed: \(reason)")
            return false
        case nil:
            AppLog.w("PinManagerLite: refresh timed out after \(seconds)s")
            return false
        }
    }
}
