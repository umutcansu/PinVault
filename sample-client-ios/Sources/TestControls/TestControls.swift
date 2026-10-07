#if TEST_CONTROLS
import Foundation
import SwiftUI
import PinVault
import PinVaultE2E

/// Test kontrolleri: yalnızca **Debug** ve **E2E** derlemelerinde vardır (TEST_CONTROLS).
/// Release derlemesi bunun yerine Sources/Release altındaki boş karşılığını alır;
/// aşağıdakilerin hiçbiri Release ikilisinde yoktur:
///
/// - Ayarlar ve Depolama ekranları (mod değiştirme, gereken imza sayısını değiştirme,
///   sıfırlama, planlı işi iptal etme, Keychain kayıt listesi),
/// - E2E denetim kanalı (PinVaultE2E: control.json, report.json) ve açılış modu,
/// - token'sız otomatik kayıt,
/// - elle P12 içe aktarma.
///
/// Bunlar kütüphaneyi denemek ve uçtan uca testler içindir. Gerçek bir kullanıcının
/// telefonunda bulunmaları, uygulamayı pin güncellemelerinden ve iptalden koparmanın ya
/// da güvenliği düşürmenin yolu olurdu.
enum TestControls {

    /// Açılışta bir kez, PinVault başlamadan önce: E2E denetim kanalını açar (control.json
    /// okunur, saat kaydırması ve yönlendirmeler kütüphaneye verilir, report.json yazılır)
    /// ve control.json'daki `mode`'u uygular. Bu, Android'deki `am start … --es mode <MOD>`
    /// açılış ekinin karşılığıdır: yalnızca tam olarak bilinen bir mod adı kabul edilir,
    /// aktif moddan farklıysa kaydedilir ve PinVault o modda başlar.
    @MainActor
    static func onAppStart() {
        let controls = E2EControls.shared
        controls.start()
        if let mode = modeFrom(controls.control?.mode), mode != AppSettings.mode() {
            AppLog.d("E2E control: launch mode \(mode.rawValue)")
            AppSettings.setMode(mode)
        }
    }

    /// Yalnızca tam olarak bilinen bir mod adı (büyük harfle, `AppSettings.Mode`); başka her değer yok sayılır.
    static func modeFrom(_ raw: String?) -> AppSettings.Mode? {
        guard let raw, raw.count <= 32 else { return nil }
        return AppSettings.Mode(rawValue: raw)
    }

    // ── Otomatik kayıt ───────────────────────────────────────────────────────

    /// Token yerine cihaz kimliğiyle kayıt; sunucu yalnızca açık kayıt ya da kodsuz başvuru modunda kabul eder.
    static func autoEnroll() async -> ClientCertEnrollmentResult {
        await TestEnrollment.autoEnroll()
    }

    // ── Elle yüklenen P12 ────────────────────────────────────────────────────

    /// mTLS bloğunda kullanılacak elle yüklenmiş kimlik; yoksa nil.
    static func loadManualIdentity() -> ManualP12Identity? {
        AppSettings.useManualP12() ? ManualP12Store.load() : nil
    }

    /// ``loadManualIdentity()``'nin döndürdüğü kimliği bloğa istemci sertifikası olarak verir.
    static func applyManualIdentity(_ block: ConfigApiBlock.Builder, _ identity: ManualP12Identity?) {
        guard let identity else { return }
        // P12 telefonda Keychain anahtarıyla şifreli durur (ManualP12Store).
        block.clientKeystore(identity.p12, password: identity.password)
    }

    /// Elle yüklenen P12'yi mTLS bloğunun istemci sertifikası yapar ya da bırakır.
    ///
    /// İçe aktarma: `Library/Application Support/manual-client.p12` kullanıcının girdiği
    /// parolayla açılır, Keychain anahtarıyla şifreli bir pakete çevrilir ve düz dosya
    /// silinir (ManualP12Store). Bırakma: şifreli paket ve anahtarı silinir; yeniden
    /// kullanmak için dosya tekrar konur.
    @MainActor
    static func toggleManualP12(state: ActionState, password: Binding<String>) {
        if AppSettings.useManualP12() {
            state.runAction(S.mtlsManualDropping) {
                AppSettings.setUseManualP12(false)
                ManualP12Store.clear()
                let model = await AppModel.shared
                await model.restartPinVault()
                _ = await model.awaitSettled(timeout: 60)
                return S.mtlsManualDropped
            }
            return
        }
        // Parola alanını okur ve hemen boşaltır: ekranda kalmasın.
        let secret = password.wrappedValue
        password.wrappedValue = ""
        if secret.isEmpty && !ManualP12Store.isImported() {
            state.showResult(S.mtlsManualPasswordRequired)
            return
        }
        state.runAction(S.mtlsManualImporting) {
            let cn: String
            if ManualP12Store.hasInbox() {
                if secret.isEmpty { return S.mtlsManualPasswordRequired }
                do {
                    cn = try ManualP12Store.importFromInbox(password: secret)
                } catch ManualP12Store.Failure.wrongPassword {
                    return S.mtlsManualWrongPassword
                }
            } else {
                // Daha önce içe aktarılmış (şifreli kopya duruyor): yeniden kullan.
                guard let identity = ManualP12Store.load() else {
                    return S.mtlsManualMissing(ManualP12Store.inboxFile)
                }
                cn = try ManualP12Store.commonName(identity)
            }
            AppSettings.setUseManualP12(true)
            let model = await AppModel.shared
            await model.restartPinVault()
            let settled = await model.awaitSettled(timeout: 60)
            let initState = settled.phase == .ready
                ? "Hazır — config \(settled.detail ?? "null")"
                : "başlatılamadı: \(settled.detail ?? "null")"
            return S.mtlsManualImported(cn, initState)
        }
    }
}
#endif
