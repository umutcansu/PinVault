import Foundation
import PinVault

/// Ekranların ortak iskeleti (Android: ActionActivity): bir düğmeye basınca işi arka
/// planda çalıştırır, sonucu durum kutusuna yazar ve iş sürerken düğmeleri kilitler.
///
/// Her sonucun altına "#<sıra> · saat" eklenir. Aynı sonuç art arda geldiğinde de
/// ekranın güncellendiği görülür; uçtan uca testler (sample-e2e) yeni sonucu
/// eskisinden bununla ayırır. Sıra ekran başınadır: ekran her açılışta 1'den başlar.
@MainActor
class ActionState: ObservableObject {
    /// Durum kutusunun (`statusView`) metni.
    @Published var status: String
    @Published private(set) var busy = false

    private var actionSeq = 0
    /// Ekran kapandı (Android: onDestroy → io.shutdown): uzun süren bekleme döngüleri durur.
    private(set) var closed = false

    init(status: String = "") {
        self.status = status
    }

    func setBusy(_ value: Bool) {
        busy = value
    }

    func close() {
        closed = true
    }

    /// [action]'ı arka planda çalıştırır; dönen metin durum kutusuna yazılır.
    /// Beklenmeyen bir hata da sonuç olarak gösterilir.
    func runAction(_ pendingText: String, _ action: @escaping @Sendable () async throws -> String) {
        setBusy(true)
        status = pendingText
        Task.detached(priority: .userInitiated) { [weak self] in
            let text: String
            do {
                text = try await action()
            } catch {
                AppLog.e("Action failed", error)
                text = "❌ \(ErrorText.block(error))"
            }
            await self?.showResult(text)
        }
    }

    func showResult(_ text: String) {
        stampResult(text)
    }

    /// Sonucu sıra ve saatle yazar ve düğmeleri açar (alt türlerin `super.showResult`'u).
    final func stampResult(_ text: String) {
        actionSeq += 1
        status = "\(text)\n\n#\(actionSeq) · \(Clock.hms())"
        setBusy(false)
    }
}

/// Pinli istekler (Android: ActionActivity.pinnedClient / pinnedGet).
enum PinnedRequests {

    /// PinVault ile pinlenmiş yeni bir oturum (`PinVault.applyTo`). Cihaz mTLS için
    /// kayıtlıysa istemci sertifikasını da sunar. Pin'ler her el sıkışmada güncel
    /// config'ten okunur; config yokken bağlantıyı reddeder. Mock host adları config'teki
    /// `resolve` ile host IP'sine gider (Android: MockDns).
    static func pinnedClient() -> PinnedSession {
        let configuration = URLSessionConfiguration.ephemeral
        // OkHttp'nin varsayılanları gibi 10 sn.
        configuration.timeoutIntervalForRequest = 10
        configuration.timeoutIntervalForResource = 30
        return PinVault.shared.applyTo(configuration)
    }

    /// [url]'ye pinli GET; sonucu "✅ [ok] HTTP n" ya da "❌ [fail] <hata>" olarak
    /// döndürür. Önemli olan TLS el sıkışmasının ve pin doğrulamasının geçmesidir; gövdeye
    /// yalnızca mTLS dinleyicisinin iptal cevabı için bakılır. [close] true ise oturum
    /// istekten sonra kapatılır (her istek kendi oturumuyla, Android'deki gibi).
    static func pinnedGet(
        _ session: PinnedSession, _ url: String, ok: String, fail: String, note: String, close: Bool = true
    ) async -> String {
        defer { if close { session.invalidateAndCancel() } }
        do {
            guard let target = URL(string: url) else { throw SampleError.illegalArgument("Geçersiz adres: \(url)") }
            let (data, response) = try await session.data(from: target)
            let code = (response as? HTTPURLResponse)?.statusCode ?? 0
            AppLog.d("\(url) → \(code)")
            // mTLS dinleyicisi iptal edilmiş kimliği el sıkışmada değil, her istekte reddeder
            // (403 reenroll_required): bağlantı kuruldu ama sertifika kabul edilmedi.
            if code == 403, String(decoding: data, as: UTF8.self).contains("reenroll_required") {
                return "❌ \(fail)\nHTTP 403\n(sertifika kabul edilmedi: kimlik iptal edilmiş, yeniden kayıt gerekli)"
            }
            return "✅ \(ok)\nHTTP \(code)\n(\(note))"
        } catch {
            AppLog.e("\(url) failed", error)
            return "❌ \(fail)\n\(ErrorText.block(error))"
        }
    }
}
