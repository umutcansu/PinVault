import XCTest
import PinVault
@testable import PinVaultFlutterCore

/// Review 2026-11-12: fields a release build still took from Dart although they
/// weaken what the native security file sets up.
final class ReleaseFieldRulesTests: XCTestCase {
    let key = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEktplZyI6Mtuhuih3wbgVRAWKarJhn8pm3YaUa4QxaBHfwEbuSrXOpoMG6PjwYcwjpfmArLr1fk1Rsn9H6lh6EQ=="
    let pinA = "x4qg2Ca8dUOIfMYEGlR50p4ygjFpJb7emumz/ppRMSI="
    let pinB = "609TJ66QBh0UWFLa4K85gbE/n8A3FGbboV5YlwWP3G8="
    let tokens = VaultTokenStore()

    var block: String {
        #""id":"default","url":"https://h.example:8081/","bootstrapPins":[{"hostname":"h.example","sha256":["\#(pinA)","\#(pinB)"]}],"signaturePublicKeys":["\#(key)"]"#
    }
    let api = #""configApis":[{"id":"default","url":"https://h.example:8081/""#

    func file(_ extraBlock: String = "", top: String = "") throws -> NativeSecurity {
        try NativeSecurity.parse(#"{"configApis":[{\#(block)\#(extraBlock)}]\#(top)}"#, source: "pinvault_security.json")
    }

    @discardableResult
    func parse(_ json: String, native: NativeSecurity?, release: Bool = true) throws -> ParsedConfig {
        try ConfigParser.parse(json, tokens: tokens, guardFactory: { _ in ClosureEnvironmentGuard { _ in true } },
                               listener: nil, native: native, release: release, noFileAllowed: native == nil)
    }

    func assertRefused(_ json: String, native: NativeSecurity?, release: Bool = true, _ fragments: String...,
                       file: StaticString = #filePath, line: UInt = #line) {
        do {
            try parse(json, native: native, release: release)
            XCTFail("accepted: \(json.prefix(200))", file: file, line: line)
        } catch {
            let message = (error as? BridgeInputError)?.message ?? (error as? PinVaultError)?.message ?? "\(error)"
            for f in fragments { XCTAssertTrue(message.contains(f), "'\(message)' lacks '\(f)'", file: file, line: line) }
        }
    }

    func testHealthEndpointComesFromTheFileInAReleaseBuild() throws {
        assertRefused(#"{\#(api),"healthEndpoint":"api/v1/certificate-config"}]}"#, native: try file(), "healthEndpoint", "native security file")
        let declared = try file(#","healthEndpoint":"status""#)
        XCTAssertEqual(try parse(#"{\#(api)}]}"#, native: declared).config.configApis["default"]?.healthEndpoint, "status")
        XCTAssertEqual(try parse(#"{\#(api),"healthEndpoint":"status"}]}"#, native: declared).config.configApis["default"]?.healthEndpoint, "status")
        assertRefused(#"{\#(api),"healthEndpoint":"elsewhere"}]}"#, native: declared, release: false, "healthEndpoint", "fixed")
        // A debug build takes it from Dart as before.
        XCTAssertEqual(try parse(#"{\#(api),"healthEndpoint":"elsewhere"}]}"#, native: try file(), release: false)
                        .config.configApis["default"]?.healthEndpoint, "elsewhere")
        // The file's value is held to the endpoint rule.
        XCTAssertThrowsError(try file(#","healthEndpoint":"https://evil.example/ok""#))
    }

    func testManagedTrustRootsAreARelaxationTheFileAllows() throws {
        assertRefused(#"{\#(api)}],"managedTrustRoots":true}"#, native: try file(), "managedTrustRoots", "require.managedTrustRoots")
        // Without a native file (the Info.plist allows it) the anchors come from Dart, the relaxation still does not.
        assertRefused(#"{"configApis":[{\#(block)}],"managedTrustRoots":true}"#, native: nil, "managedTrustRoots")
        XCTAssertTrue(try parse(#"{\#(api)}],"managedTrustRoots":true}"#, native: try file(top: #","require":{"managedTrustRoots":true}"#))
                        .config.managedTrustRoots)
        XCTAssertTrue(try parse(#"{\#(api)}],"managedTrustRoots":true}"#, native: try file(), release: false).config.managedTrustRoots)
    }

    func testTheUnlockedDeviceFallbackNeedsTheFilesConsentWhenTheFileRequiresAnUnlockedDevice() throws {
        let requires = try file(top: #","require":{"requireUnlockedDevice":true}"#)
        let fallback = #"{\#(api)}],"ios":{"requireUnlockedDeviceAllowFallback":true}}"#
        assertRefused(fallback, native: requires, "requireUnlockedDeviceAllowFallback", "does not allow the fallback")
        // In any build.
        assertRefused(fallback, native: requires, release: false, "requireUnlockedDeviceAllowFallback")
        let allows = try file(top: #","require":{"requireUnlockedDevice":true,"requireUnlockedDeviceAllowFallback":true}"#)
        XCTAssertTrue(try parse(fallback, native: allows).config.requireUnlockedDeviceFallback)
        // Dart's own requireUnlockedDevice is Dart's to soften.
        XCTAssertTrue(try parse(#"{\#(api)}],"requireUnlockedDevice":true,"ios":{"requireUnlockedDeviceAllowFallback":true}}"#, native: try file())
                        .config.requireUnlockedDeviceFallback)
    }

    func testAReleaseBuildWithANativeFileTakesVaultFilesOnlyFromItsVaultFilesSection() throws {
        assertRefused(#"{\#(api)}],"vaultFiles":[{"key":"doc","endpoint":"api/v1/vault/doc","userAuth":"NONE"}]}"#,
                      native: try file(), "vaultFiles section")
        // A debug build, and a release build with the file's declaration, are fine.
        XCTAssertNotNil(try parse(#"{\#(api)}],"vaultFiles":[{"key":"doc","endpoint":"api/v1/vault/doc"}]}"#, native: try file(), release: false)
                            .config.vaultFiles["doc"])
        XCTAssertNotNil(try parse(#"{\#(api)}],"vaultFiles":[{"key":"doc","endpoint":"api/v1/vault/doc"}]}"#,
                                  native: try file(top: #","vaultFiles":[{"key":"doc"}]"#)).config.vaultFiles["doc"])
    }

    func testTheFileCanMakeAVaultFileWipeItsStaleCopy() throws {
        let wipes = try file(top: #","vaultFiles":[{"key":"doc","wipeWhenStale":true}]"#)
        let vault = try XCTUnwrap(try parse(#"{\#(api)}],"vaultFiles":[{"key":"doc","endpoint":"api/v1/vault/doc","maxOfflineAge":{"amount":1,"unit":"DAYS"}}]}"#,
                                            native: wipes).config.vaultFiles["doc"])
        XCTAssertTrue(vault.wipeWhenStale)
    }

    func testAReleaseBuildWithANativeFileHasNoExpiredConfigGraceUnlessTheFileGivesOne() throws {
        assertRefused(#"{\#(api)}],"expiredConfigGrace":{"amount":1,"unit":"HOURS"}}"#, native: try file(), "expiredConfigGrace")
        try parse(#"{\#(api)}],"expiredConfigGrace":{"amount":0,"unit":"SECONDS"}}"#, native: try file())
        try parse(#"{\#(api)}],"expiredConfigGrace":{"amount":1,"unit":"HOURS"}}"#, native: try file(top: #","require":{"expiredConfigGraceSeconds":3600}"#))
        // A debug build, and a release build without a file, keep the 7-day rule only.
        try parse(#"{\#(api)}],"expiredConfigGrace":{"amount":1,"unit":"HOURS"}}"#, native: try file(), release: false)
        try parse(#"{"configApis":[{\#(block)}],"expiredConfigGrace":{"amount":1,"unit":"HOURS"}}"#, native: nil)
    }

    func testAReleaseBuildNeverRaisesTheClientCertificateLifetimePastTheFiles() throws {
        assertRefused(#"{\#(api),"maxClientCertLifetimeDays":3650}]}"#, native: try file(), "maxClientCertLifetimeDays", "825")
        XCTAssertEqual(try parse(#"{\#(api),"maxClientCertLifetimeDays":30}]}"#, native: try file())
                        .config.configApis["default"]?.maxClientCertLifetimeDays, 30)
        let raised = try file(#","maxClientCertLifetimeDays":1000"#)
        try parse(#"{\#(api),"maxClientCertLifetimeDays":1000}]}"#, native: raised)
        XCTAssertEqual(try parse(#"{\#(api)}]}"#, native: raised).config.configApis["default"]?.maxClientCertLifetimeDays, 1000)
        assertRefused(#"{\#(api),"maxClientCertLifetimeDays":1001}]}"#, native: raised, "maxClientCertLifetimeDays", "1000")
        // A debug build takes Dart's value.
        try parse(#"{\#(api),"maxClientCertLifetimeDays":3650}]}"#, native: try file(), release: false)
    }
}
