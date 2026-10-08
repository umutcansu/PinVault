import Foundation

/// Uygulamanın kendi ayarları: çalışma modu, telemetri seçenekleri, elle yüklenen
/// P12. Gizli bir şey içermez; düz UserDefaults'ta tutulur (Android: SharedPreferences
/// "sample_settings") ve süreç yeniden başlayınca korunur.
///
/// **Release derlemesinde** (TEST_CONTROLS yok) buradaki tercihler güvenliği
/// etkileyemez: mod her zaman ``Mode/tls``, gereken imza sayısı her zaman derlemeye
/// gömülü değer, pin kapsamı ve elle P12 kapalıdır; tercihte ne yazdığına bakılmaz.
/// Onları değiştiren ekran (Ayarlar) da yalnızca test derlemelerinde vardır.
enum AppSettings {

    /// PinVault'un nasıl kurulacağı. ``AppModel/startPinVault()`` buna göre config üretir.
    enum Mode: String, CaseIterable, Sendable {
        /// TLS Config API'den imzalı config (varsayılan). Kayıtlıysa mTLS bloğu da eklenir.
        case tls = "TLS"
        /// Config mTLS Config API üzerinden, kayıtlı istemci sertifikasıyla çekilir.
        case mtlsConfig = "MTLS_CONFIG"
        /// Özel uç yollarıyla başka bir backend (sample-e2e/lib/custom-backend.js).
        case customBackend = "CUSTOM_BACKEND"
        /// Kütüphaneden HTTP çıkmaz: config uygulama içindeki `CertificateConfigApi`'den.
        case embeddedApi = "EMBEDDED_API"
        /// Sunucusuz: uygulamaya gömülü statik pin'ler.
        case staticPins = "STATIC"

        var label: String {
            switch self {
            case .mtlsConfig: return "mTLS config"
            case .customBackend: return "özel backend"
            case .embeddedApi: return "gömülü API"
            case .staticPins: return "statik pin'ler"
            case .tls: return "TLS config"
            }
        }
    }

    private static let keyMode = "mode"
    private static let keyReportSuccess = "telemetry_report_success"
    private static let keyDedupMs = "telemetry_dedup_ms"
    private static let keyManualP12 = "mtls_manual_p12"
    private static let keyScopedPins = "scoped_pins"
    private static let keyRequiredSignatures = "required_signatures"

    private static var defaults: UserDefaults { .standard }

    /// Çalışma modu. Release'te her zaman TLS: diğer modlar (statik, gömülü, özel
    /// backend) uygulamayı sunucunun pin güncellemelerinden ve iptalden koparabildiği
    /// için yalnızca test derlemelerinde seçilebilir.
    static func mode() -> Mode {
        #if TEST_CONTROLS
        return defaults.string(forKey: keyMode).flatMap(Mode.init(rawValue:)) ?? .tls
        #else
        return .tls
        #endif
    }

    static func setMode(_ mode: Mode) {
        #if TEST_CONTROLS
        defaults.set(mode.rawValue, forKey: keyMode)
        #endif
    }

    /// Başarılı el sıkışmalar da dashboard'a raporlansın mı (varsayılan evet).
    static func reportSuccess() -> Bool {
        defaults.object(forKey: keyReportSuccess) as? Bool ?? true
    }

    /// Aynı host + pin + sürüm için tekrar eden raporların bastırılma penceresi (ms).
    static func dedupMs() -> Int64 {
        (defaults.object(forKey: keyDedupMs) as? NSNumber)?.int64Value ?? 0
    }

    static func setTelemetry(reportSuccess: Bool, dedupMs: Int64) {
        defaults.set(reportSuccess, forKey: keyReportSuccess)
        defaults.set(NSNumber(value: max(0, dedupMs)), forKey: keyDedupMs)
    }

    /// Config başına gereken imza sayısı (m-of-n). Taban, derlemeye gömülü değerdir
    /// (sample-host.properties → host.requiredSignatures) ve hiçbir derlemede altına
    /// inilmez: tercih yalnızca YÜKSELTEBİLİR. Release'te tercih hiç okunmaz.
    static func requiredSignatures() -> Int {
        let floor = max(1, SampleHostConfig.hostRequiredSignatures)
        #if TEST_CONTROLS
        let stored = (defaults.object(forKey: keyRequiredSignatures) as? NSNumber)?.intValue ?? floor
        return max(floor, stored)
        #else
        return floor
        #endif
    }

    static func setRequiredSignatures(_ value: Int) {
        #if TEST_CONTROLS
        defaults.set(NSNumber(value: value), forKey: keyRequiredSignatures)
        #endif
    }

    /// Config çekilirken yalnızca hedef host'un pin'leri istensin mi
    /// (`ConfigApiBlock.wantPinsFor`). Açıkken kütüphane isteğe `?hosts=<hedef>` ve
    /// `X-Device-Id` ekler; sunucu cihazın host ACL'ine göre filtreler. Test kontrolü.
    static func scopedPins() -> Bool {
        #if TEST_CONTROLS
        return defaults.bool(forKey: keyScopedPins)
        #else
        return false
        #endif
    }

    static func setScopedPins(_ value: Bool) {
        #if TEST_CONTROLS
        defaults.set(value, forKey: keyScopedPins)
        #endif
    }

    /// mTLS için kayıt yerine elle yüklenen P12 kullanılsın mı. Test kontrolü.
    static func useManualP12() -> Bool {
        #if TEST_CONTROLS
        return defaults.bool(forKey: keyManualP12)
        #else
        return false
        #endif
    }

    static func setUseManualP12(_ value: Bool) {
        #if TEST_CONTROLS
        defaults.set(value, forKey: keyManualP12)
        #endif
    }
}
