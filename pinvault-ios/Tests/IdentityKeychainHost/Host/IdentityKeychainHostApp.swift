import SwiftUI

/// The empty app the Keychain / Secure Enclave tests run inside. A package
/// test bundle runs in the simulator's `xctest` process, which has no
/// Keychain entitlement (every Keychain call answers -34018); an ad-hoc
/// signed app has one, so these tests are hosted here. See `../project.yml`.
@main
struct IdentityKeychainHostApp: App {
    var body: some Scene {
        WindowGroup { Text("PinVault identity Keychain test host") }
    }
}
