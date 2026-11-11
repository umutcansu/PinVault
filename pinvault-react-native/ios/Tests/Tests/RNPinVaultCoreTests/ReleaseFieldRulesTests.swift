import XCTest
import PinVault
@testable import RNPinVaultCore

/// Review 2026-11-12: fields a release build still took from JS although they
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
    func parse(_ js: String, _ native: NativeSecurity?, release: Bool = true, reactNetworkingEnabled: Bool = true) throws -> ParsedConfig {
        try ConfigParser.parse(js, tokens: tokens, guardFactory: { _ in ClosureEnvironmentGuard { _ in true } }, listener: nil,
                               native: native, release: release, noFileAllowed: native == nil,
                               reactNetworkingEnabled: reactNetworkingEnabled)
    }

    func assertRefused(_ js: String, _ native: NativeSecurity?, release: Bool = true, _ fragments: String...,
                       file: StaticString = #filePath, line: UInt = #line) {
        do {
            try parse(js, native, release: release)
            XCTFail("accepted: \(js.prefix(200))", file: file, line: line)
        } catch {
            let message = (error as? BridgeInputError)?.message ?? (error as? PinVaultError)?.message ?? "\(error)"
            for f in fragments { XCTAssertTrue(message.contains(f), "'\(message)' lacks '\(f)'", file: file, line: line) }
        }
    }

    func testHealthEndpointComesFromTheFileInAReleaseBuild() throws {
        assertRefused(#"{\#(api),"healthEndpoint":"api/v1/certificate-config"}]}"#, try file(), "healthEndpoint", "native security file")
        let declared = try file(#","healthEndpoint":"status""#)
        XCTAssertEqual(try parse(#"{\#(api)}]}"#, declared).config.configApis["default"]?.healthEndpoint, "status")
        XCTAssertNoThrow(try parse(#"{\#(api),"healthEndpoint":"status"}]}"#, declared))
        assertRefused(#"{\#(api),"healthEndpoint":"elsewhere"}]}"#, declared, "healthEndpoint")
        // A debug build takes it from JS as before (the file's value stays fixed where it names one).
        XCTAssertEqual(try parse(#"{\#(api),"healthEndpoint":"elsewhere"}]}"#, try file(), release: false)
                        .config.configApis["default"]?.healthEndpoint, "elsewhere")
        assertRefused(#"{\#(api),"healthEndpoint":"elsewhere"}]}"#, declared, release: false, "healthEndpoint", "fixed")
        // The file's path is held to the endpoint rule.
        XCTAssertThrowsError(try file(#","healthEndpoint":"https://evil.example/ok""#))
    }

    func testManagedTrustRootsAreARelaxationTheFileAllows() throws {
        assertRefused(#"{\#(api)}],"managedTrustRoots":true}"#, try file(), "managedTrustRoots")
        // Without a native file (the Info.plist allows it) the anchors come from JS, the relaxation still does not.
        assertRefused(#"{"configApis":[{\#(block)}],"managedTrustRoots":true}"#, nil, "managedTrustRoots")
        let allowed = try parse(#"{\#(api)}],"managedTrustRoots":true}"#, try file(top: #","require":{"managedTrustRoots":true}"#))
        XCTAssertTrue(allowed.config.managedTrustRoots)
        XCTAssertTrue(try parse(#"{\#(api)}],"managedTrustRoots":true}"#, try file(), release: false).config.managedTrustRoots)
    }

    func testTheUnlockedDeviceFallbackNeedsTheFilesConsentWhenTheFileRequiresAnUnlockedDevice() throws {
        let requires = try file(top: #","require":{"requireUnlockedDevice":true}"#)
        let js = #"{\#(api)}],"ios":{"requireUnlockedDeviceAllowFallback":true}}"#
        assertRefused(js, requires, "requireUnlockedDeviceAllowFallback")
        // In any build: the file's protection is not JS's to trade.
        assertRefused(js, requires, release: false, "requireUnlockedDeviceAllowFallback")
        let allows = try file(top: #","require":{"requireUnlockedDevice":true,"requireUnlockedDeviceAllowFallback":true}"#)
        let p = try parse(js, allows)
        XCTAssertTrue(p.config.requireUnlockedDevice)
        XCTAssertTrue(p.config.requireUnlockedDeviceFallback)
        // Where only JS asks for an unlocked device, JS may allow the fallback too.
        XCTAssertTrue(try parse(#"{\#(api)}],"requireUnlockedDevice":true,"ios":{"requireUnlockedDeviceAllowFallback":true}}"#, try file())
                        .config.requireUnlockedDeviceFallback)
    }

    func testReactNativeNetworkingStaysRequiredPinnedInAReleaseBuildUnlessTheFileAllowsOtherwise() throws {
        let off = #"{\#(api)}],"requirePinnedReactNativeNetworking":false}"#
        assertRefused(off, try file(), "requirePinnedReactNativeNetworking", "allowUnpinnedReactNativeNetworking")
        assertRefused(#"{"configApis":[{\#(block)}],"requirePinnedReactNativeNetworking":false}"#, nil, "requirePinnedReactNativeNetworking")
        let allows = try file(top: #","require":{"allowUnpinnedReactNativeNetworking":true}"#)
        XCTAssertFalse(try parse(off, allows).requirePinnedReactNativeNetworking)
        // A debug build, and an app whose Info.plist opted out natively, take JS's false.
        XCTAssertFalse(try parse(off, try file(), release: false).requirePinnedReactNativeNetworking)
        XCTAssertFalse(try parse(off, try file(), reactNetworkingEnabled: false).requirePinnedReactNativeNetworking)
        XCTAssertTrue(try parse(#"{\#(api)}],"requirePinnedReactNativeNetworking":true}"#, try file()).requirePinnedReactNativeNetworking)
    }

    func testAReleaseBuildWithANativeFileTakesVaultFilesOnlyFromItsVaultFilesSection() throws {
        assertRefused(#"{\#(api)}],"vaultFiles":[{"key":"doc","endpoint":"api/v1/vault/doc","userAuth":"NONE"}]}"#, try file(),
                      "'doc' is not declared", "vaultFiles section")
        // A debug build, a release build with the file's declaration, and one without a file are fine.
        XCTAssertNoThrow(try parse(#"{\#(api)}],"vaultFiles":[{"key":"doc","endpoint":"api/v1/vault/doc"}]}"#, try file(), release: false))
        XCTAssertNoThrow(try parse(#"{\#(api)}],"vaultFiles":[{"key":"doc","endpoint":"api/v1/vault/doc"}]}"#,
                                   try file(top: #","vaultFiles":[{"key":"doc"}]"#)))
        XCTAssertNoThrow(try parse(#"{"configApis":[{\#(block)}],"vaultFiles":[{"key":"doc","endpoint":"api/v1/vault/doc"}]}"#, nil))
    }

    func testTheFileCanMakeAVaultFileWipeItsStaleCopy() throws {
        let wipes = try file(top: #","vaultFiles":[{"key":"doc","wipeWhenStale":true}]"#)
        let vault = try XCTUnwrap(try parse(
            #"{\#(api)}],"vaultFiles":[{"key":"doc","endpoint":"api/v1/vault/doc","maxOfflineAge":{"amount":1,"unit":"DAYS"}}]}"#, wipes
        ).config.vaultFiles["doc"])
        XCTAssertTrue(vault.wipeWhenStale)
        let plain = try XCTUnwrap(try parse(
            #"{\#(api)}],"vaultFiles":[{"key":"doc","endpoint":"api/v1/vault/doc","maxOfflineAge":{"amount":1,"unit":"DAYS"}}]}"#,
            try file(top: #","vaultFiles":[{"key":"doc"}]"#)
        ).config.vaultFiles["doc"])
        XCTAssertFalse(plain.wipeWhenStale)
    }

    func testAReleaseBuildWithANativeFileHasNoExpiredConfigGraceUnlessTheFileGivesOne() throws {
        let hour = #"{\#(api)}],"expiredConfigGrace":{"amount":1,"unit":"HOURS"}}"#
        assertRefused(hour, try file(), "expiredConfigGrace", "(0 s)")
        XCTAssertNoThrow(try parse(#"{\#(api)}],"expiredConfigGrace":{"amount":0,"unit":"SECONDS"}}"#, try file()))
        XCTAssertEqual(try parse(hour, try file(top: #","require":{"expiredConfigGraceSeconds":3600}"#)).config.expiredConfigGraceMs, 3_600_000)
        // A debug build, and a release build without a file (7-day cap), take it.
        XCTAssertNoThrow(try parse(hour, try file(), release: false))
        XCTAssertNoThrow(try parse(#"{"configApis":[{\#(block)}],"expiredConfigGrace":{"amount":1,"unit":"HOURS"}}"#, nil))
    }

    func testAReleaseBuildNeverRaisesTheClientCertificateLifetimePastTheFiles() throws {
        assertRefused(#"{\#(api),"maxClientCertLifetimeDays":3650}]}"#, try file(), "maxClientCertLifetimeDays", "825")
        XCTAssertEqual(try parse(#"{\#(api),"maxClientCertLifetimeDays":30}]}"#, try file()).config.configApis["default"]?.maxClientCertLifetimeDays, 30)
        let longer = try file(#","maxClientCertLifetimeDays":1000"#)
        XCTAssertNoThrow(try parse(#"{\#(api),"maxClientCertLifetimeDays":1000}]}"#, longer))
        XCTAssertEqual(try parse(#"{\#(api)}]}"#, longer).config.configApis["default"]?.maxClientCertLifetimeDays, 1000, "the file's value when JS gives none")
        assertRefused(#"{\#(api),"maxClientCertLifetimeDays":1001}]}"#, longer, "maxClientCertLifetimeDays", "1000")
        XCTAssertEqual(try parse(#"{\#(api),"maxClientCertLifetimeDays":3650}]}"#, try file(), release: false)
                        .config.configApis["default"]?.maxClientCertLifetimeDays, 3650)
    }
}
