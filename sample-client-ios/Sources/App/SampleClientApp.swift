import SwiftUI
import UIKit

/// PinVault sample client (iOS). Android'deki sample-client'ın karşılığı: aynı ekranlar,
/// aynı görünüm kimlikleri, aynı Türkçe metinler (sample-e2e ikisini de aynı sayfa
/// nesnesiyle sürer). Uygulama katmanı ``AppModel``'de.
@main
struct SampleClientApp: App {
    @UIApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @Environment(\.scenePhase) private var scenePhase

    var body: some Scene {
        WindowGroup {
            RootView()
                #if !TEST_CONTROLS
                // Ekranlar token, kayıt kodu, cihaz kimliği, pin ve dosya içeriği gösteriyor:
                // uygulama öne gelmeyi bırakınca (uygulama değiştirici önizlemesi dahil) içerik
                // örtülür (Android: FLAG_SECURE). Test derlemeleri hiç örtmez (kanıt görüntüleri;
                // Android'de -Psample.e2eScreenshots=true).
                .privacyCover(hidden: scenePhase != .active)
                #endif
        }
    }
}

/// Açılış (Android: App.onCreate). BGTask işleyicisi açılış bitmeden kaydedilmeli; bu
/// yüzden SwiftUI `App.init` yerine `didFinishLaunching`.
final class AppDelegate: NSObject, UIApplicationDelegate {
    func application(
        _ application: UIApplication,
        didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil
    ) -> Bool {
        AppModel.shared.onLaunch()
        return true
    }
}

/// Ekranların kökü: ana ekran ve ondan açılan ekranlar (Android: aktivite yığını).
struct RootView: View {
    @State private var path: [Route] = []

    var body: some View {
        NavigationStack(path: $path) {
            MainView(path: $path)
                .navigationDestination(for: Route.self) { route in
                    switch route {
                    case .mtls: MtlsView()
                    case .vault: VaultView()
                    #if TEST_CONTROLS
                    case .storage: StorageView()
                    case .settings: SettingsView()
                    #endif
                    }
                }
        }
    }
}

#if !TEST_CONTROLS
private struct PrivacyCover: ViewModifier {
    let hidden: Bool

    func body(content: Content) -> some View {
        content
            .blur(radius: hidden ? 24 : 0)
            .overlay {
                if hidden {
                    Rectangle().fill(.regularMaterial).ignoresSafeArea()
                }
            }
    }
}

extension View {
    func privacyCover(hidden: Bool) -> some View {
        modifier(PrivacyCover(hidden: hidden))
    }
}
#endif
