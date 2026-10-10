// swift-tools-version: 6.0
//
// XCTest for the plugin's Swift core (Classes/Core: strict JSON, config parser,
// result mapping, fetch parsing, the Dart environment guard). Those files import
// only Foundation and PinVault, so they build and run on the Mac against the
// PinVault package of this repository — no simulator, no Flutter.
//
//   cd pinvault-flutter/ios/Tests && swift test
import PackageDescription

let package = Package(
    name: "PinVaultFlutterCoreTests",
    platforms: [.iOS(.v16), .macOS(.v13)],
    dependencies: [
        .package(name: "PinVault", path: "../../.."),
    ],
    targets: [
        .target(
            name: "PinVaultFlutterCore",
            dependencies: [.product(name: "PinVault", package: "PinVault")],
            path: "Core", // symlink to ../Classes/Core (SwiftPM keeps targets inside the package root)
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
        .testTarget(
            name: "PinVaultFlutterCoreTests",
            dependencies: ["PinVaultFlutterCore", .product(name: "PinVault", package: "PinVault")],
            path: "Tests/PinVaultFlutterCoreTests",
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
    ]
)
