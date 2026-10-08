// swift-tools-version: 6.0
//
// XCTest for the plugin's Swift core (../Core: strict JSON, config parser,
// result mapping, fetch parsing, the JS environment guard). Those files import
// only Foundation and PinVault, so they build and run on the Mac against the
// PinVault package of this repository — no simulator, no React Native.
//
//   cd pinvault-react-native/ios/Tests && swift test
import PackageDescription

let package = Package(
    name: "RNPinVaultCoreTests",
    platforms: [.iOS(.v16), .macOS(.v13)],
    dependencies: [
        .package(name: "PinVault", path: "../../.."),
    ],
    targets: [
        .target(
            name: "RNPinVaultCore",
            dependencies: [.product(name: "PinVault", package: "PinVault")],
            path: "Core", // symlink to ../Core (SwiftPM keeps targets inside the package root)
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
        .testTarget(
            name: "RNPinVaultCoreTests",
            dependencies: ["RNPinVaultCore", .product(name: "PinVault", package: "PinVault")],
            path: "Tests/RNPinVaultCoreTests",
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
    ]
)
