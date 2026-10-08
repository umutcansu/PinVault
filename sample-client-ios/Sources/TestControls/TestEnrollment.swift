#if TEST_CONTROLS
import PinVault

/// Yalnızca Debug ve E2E derlemelerinde: token'sız "otomatik kayıt". Release'te bu dosya
/// derlenmez; uygulama yalnızca yöneticinin verdiği token ya da kayıt koduyla kayıt olur.
enum TestEnrollment {

    /// `PinVault.autoEnrollForResult`: token yerine cihaz kimliğiyle (identifierForVendor)
    /// kayıt. Sunucu yalnızca `ENROLLMENT_MODE=open` ya da kodsuz başvurular açıkken kabul eder.
    static func autoEnroll() async -> ClientCertEnrollmentResult {
        await PinVault.shared.autoEnrollForResult()
    }
}
#endif
