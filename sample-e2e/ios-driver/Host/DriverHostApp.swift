// UI test paketinin istediği boş ana uygulama. Sürücü onu hiç açmaz; örnek
// uygulamaya XCUIApplication(bundleIdentifier:) ile bağlanır.
import SwiftUI

@main
struct DriverHostApp: App {
    var body: some Scene {
        WindowGroup { Text("PinVault E2E sürücüsü") }
    }
}
