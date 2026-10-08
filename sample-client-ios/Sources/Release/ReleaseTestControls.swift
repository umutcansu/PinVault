#if !TEST_CONTROLS
import Foundation
import PinVault

/// Release'te elle P12 yok: bu tür hiç değer almaz (test derlemelerinde ManualP12Store).
typealias ManualP12Identity = Never

/// Release derlemesindeki karşılık: test kontrollerinin hiçbiri yok (Android:
/// src/release/…/TestControls.java).
///
/// Debug ve E2E derlemeleri bunun yerine Sources/TestControls altındakini alır (Ayarlar
/// ve Depolama ekranları, E2E denetim kanalı ve açılış modu, otomatik kayıt, elle P12).
/// Burada hepsi boştur: o ekranlar ve kod yolları Release ikilisine hiç girmez,
/// PinVaultE2E de bağlanmaz.
enum TestControls {

    /// Eski derlemelerin bıraktığı elle P12 dosyaları ve Keychain anahtarı.
    private static let manualP12Files = ["manual-client.p12", "manual-client.sealed", "manual-client.sealed.tmp"]
    private static let manualP12KeyAccount = "sample_manual_p12"

    /// Açılışta bir kez. Elle P12 Release'te kullanılmaz; önceki bir derlemeden kalmış düz
    /// ya da şifreli P12 dosyası ve onu açan Keychain anahtarı varsa silinir: kullanılmayan
    /// bir özel anahtar telefonda durmasın.
    @MainActor
    static func onAppStart() {
        for name in manualP12Files {
            AppFiles.wipe(AppFiles.applicationSupport.appendingPathComponent(name))
        }
        Keychain.delete(manualP12KeyAccount)
    }

    /// Elle P12 Release'te yok.
    static func loadManualIdentity() -> ManualP12Identity? {
        nil
    }

    static func applyManualIdentity(_ block: ConfigApiBlock.Builder, _ identity: ManualP12Identity?) {
        // Bilerek boş.
    }
}
#endif
