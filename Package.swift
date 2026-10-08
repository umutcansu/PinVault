// swift-tools-version: 6.0
//
// PinVault for iOS. The manifest sits at the repository root because SwiftPM
// resolves packages by git URL; the sources live under pinvault-ios/ (see
// pinvault-ios/PORTING.md).

import PackageDescription

let package = Package(
    name: "PinVault",
    platforms: [.iOS(.v16), .macOS(.v13)],
    products: [
        .library(name: "PinVault", targets: ["PinVault"]),
        // Test-control glue for E2E builds of the sample app only.
        .library(name: "PinVaultE2E", targets: ["PinVaultE2E"]),
    ],
    targets: [
        .target(
            name: "PinVault",
            path: "pinvault-ios/Sources/PinVault",
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
        .target(
            name: "PinVaultE2E",
            dependencies: ["PinVault"],
            path: "pinvault-ios/Sources/PinVaultE2E",
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
        .testTarget(
            name: "PinVaultTests",
            dependencies: ["PinVault", "PinVaultE2E"],
            path: "pinvault-ios/Tests/PinVaultTests",
            resources: [.copy("Fixtures")],
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
    ]
)
