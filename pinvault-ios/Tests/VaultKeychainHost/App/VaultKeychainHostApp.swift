import SwiftUI

/// A host app for the Keychain / Face ID tests of the vault layer: SwiftPM test
/// bundles run in the `xctest` tool, which has no Keychain entitlement on the
/// simulator (errSecMissingEntitlement, -34018: those tests skip) and no window
/// for the LocalAuthentication sheet. This app compiles the library under the
/// module name `PinVault`, so the same test files run hosted by it.
@main
struct VaultKeychainHostApp: App {
    var body: some Scene {
        WindowGroup { Text("PinVault vault Keychain host") }
    }
}
