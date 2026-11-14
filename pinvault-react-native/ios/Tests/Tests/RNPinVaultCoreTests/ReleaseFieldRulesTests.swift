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

    // Review 2026-11-14 (K1): a bare entry used to leave the three fields to the bundle.
    func testAVaultFieldTheNativeEntryLeavesOutIsTheLibraryDefaultInAReleaseBuildNeverTheJSValue() throws {
        let bare = try file(top: #","vaultFiles":[{"key":"doc"}]"#)
        func doc(_ extra: String) -> String { #"{\#(api)}],"vaultFiles":[{"key":"doc","endpoint":"api/v1/vault/doc"\#(extra)}]}"# }
        assertRefused(doc(#","signaturePublicKey":"\#(key)""#), bare, "vaultFiles[0].signaturePublicKey", "does not give signaturePublicKey", "only from there")
        assertRefused(doc(#","encryption":"PLAIN""#), bare, "vaultFiles[0].encryption", "does not give encryption", "only from there")
        assertRefused(doc(#","userAuth":"NONE""#), bare, "vaultFiles[0].userAuth", "does not give userAuth", "only from there")
        assertRefused(doc(#","encryption":"USER_AUTH","userAuth":"REQUIRED""#), bare, "does not give")
        // Nothing from JS: the library's defaults (the block's signing keys, PLAIN, NONE).
        let vault = try XCTUnwrap(try parse(doc(""), bare).config.vaultFiles["doc"])
        XCTAssertNil(vault.signaturePublicKey)
        XCTAssertEqual(vault.encryption, VaultFileEncryption.plain)
        XCTAssertEqual(vault.userAuth, UserAuth.none)
        // What the entry gives is the value; JS may repeat it.
        let full = try file(top: #","vaultFiles":[{"key":"doc","signaturePublicKey":"\#(key)","encryption":"USER_AUTH","userAuth":"REQUIRED"}]"#)
        let locked = try XCTUnwrap(try parse(doc(#","encryption":"USER_AUTH""#), full).config.vaultFiles["doc"])
        XCTAssertEqual(locked.signaturePublicKey, key)
        XCTAssertEqual(locked.userAuth, UserAuth.required)
        // An entry that gives one field leaves the other two at the default, not to JS.
        let keyOnly = try file(top: #","vaultFiles":[{"key":"doc","signaturePublicKey":"\#(key)"}]"#)
        assertRefused(doc(#","userAuth":"IF_SCREEN_LOCK""#), keyOnly, "does not give userAuth")
        // A debug build, and a release build without a native file, take them from JS as before.
        let debug = try XCTUnwrap(try parse(doc(#","encryption":"USER_AUTH","userAuth":"REQUIRED""#), bare, release: false).config.vaultFiles["doc"])
        XCTAssertEqual(debug.userAuth, UserAuth.required)
        XCTAssertNoThrow(try parse(#"{"configApis":[{\#(block)}],"vaultFiles":[{"key":"doc","endpoint":"api/v1/vault/doc","userAuth":"IF_SCREEN_LOCK"}]}"#, nil))
    }

    func testANativeVaultEntryCanFixTheFilesConfigApiEndpointAndAccessPolicy() throws {
        let fixed = try file(top: #","vaultFiles":[{"key":"doc","configApi":"default","endpoint":"api/v1/vault/doc","accessPolicy":"TOKEN"}]"#)
        func doc(_ fields: String) -> String { #"{\#(api)}],"vaultFiles":[{"key":"doc"\#(fields)}]}"# }
        // JS may leave them out or repeat them.
        let vault = try XCTUnwrap(try parse(doc(""), fixed).config.vaultFiles["doc"])
        XCTAssertEqual(vault.endpoint, "api/v1/vault/doc")
        XCTAssertEqual(vault.configApiId, "default")
        XCTAssertEqual(vault.accessPolicy, VaultFileAccessPolicy.token)
        XCTAssertNotNil(vault.accessTokenProvider)
        XCTAssertNoThrow(try parse(doc(#","endpoint":"api/v1/vault/doc","configApi":"default","accessPolicy":"TOKEN""#), fixed))
        // A different value is refused, in a debug build too.
        assertRefused(doc(#","endpoint":"api/v1/vault/other""#), fixed, "vaultFiles[0].endpoint", "native value is fixed")
        assertRefused(doc(#","configApi":"other""#), fixed, "vaultFiles[0].configApi", "native value is fixed")
        assertRefused(doc(#","accessPolicy":"PUBLIC""#), fixed, "vaultFiles[0].accessPolicy", "native value is fixed")
        assertRefused(doc(#","accessPolicy":"PUBLIC""#), fixed, release: false, "vaultFiles[0].accessPolicy", "native value is fixed")
        // An entry that does not give them leaves them to JS, as before.
        let bare = try file(top: #","vaultFiles":[{"key":"doc"}]"#)
        XCTAssertEqual(try parse(doc(#","endpoint":"elsewhere/doc","accessPolicy":"TOKEN""#), bare).config.vaultFiles["doc"]?.endpoint, "elsewhere/doc")
        assertRefused(doc(""), bare, "vaultFiles[0].endpoint", "required")
        // The file's endpoint follows the endpoint rule too.
        XCTAssertThrowsError(try file(top: #","vaultFiles":[{"key":"doc","endpoint":"../admin"}]"#)) { error in
            XCTAssertTrue(((error as? BridgeInputError)?.message ?? "").contains("'..' path segment"), "\(error)")
        }
    }

    // Review 2026-11-14 (K2): narrowing wantPinsFor took a pinned host's pins out of the signed
    // view; with managed trust roots that host is then accepted through the roots.
    func testWithManagedTrustRootsAReleaseBuildTakesWantPinsForFromTheFileOnly() throws {
        let roots = #","require":{"managedTrustRoots":true}"#
        let narrowed = #"{\#(api),"wantPinsFor":["cdn.example"]}]}"#
        assertRefused(narrowed, try file(top: roots), "configApis[0].wantPinsFor", "managed trust roots", "only from there")
        // None in the file = every host's pins.
        XCTAssertEqual(try parse(#"{\#(api)}]}"#, try file(top: roots)).config.configApis["default"]?.wantPinsFor, [])
        // The file's list is the value; JS may leave it out or repeat it (any order, any case), not change it.
        let declared = try file(#","wantPinsFor":["api.example","cdn.example"]"#, top: roots)
        XCTAssertEqual(try parse(#"{\#(api)}]}"#, declared).config.configApis["default"]?.wantPinsFor, ["api.example", "cdn.example"])
        XCTAssertNoThrow(try parse(#"{\#(api),"wantPinsFor":["CDN.example","api.example"]}]}"#, declared))
        assertRefused(narrowed, declared, "configApis[0].wantPinsFor", "native value is fixed")
        // Without managed roots: JS's list as before, unless the file gives one.
        XCTAssertEqual(try parse(narrowed, try file()).config.configApis["default"]?.wantPinsFor, ["cdn.example"])
        assertRefused(narrowed, try file(#","wantPinsFor":["api.example"]"#), "configApis[0].wantPinsFor", "native value is fixed")
        // A debug build takes JS's list with managed roots on.
        XCTAssertNoThrow(try parse(narrowed, try file(top: roots), release: false))
    }

    // Review 2026-11-14 (R-03): the rules judged only the blocks the config sent; a bundle
    // that left a declared block out dropped its pins (with managed roots: a pin -> root downgrade).
    func testAReleaseBuildRunsEveryConfigApiItsNativeFileDeclares() throws {
        func two(_ extra: String = "", top: String = "") throws -> NativeSecurity {
            let second = #"{"id":"second","url":"https://h2.example/","bootstrapPins":[{"hostname":"h2.example","sha256":["\#(pinA)","\#(pinB)"]}],"signaturePublicKeys":["\#(key)"]\#(extra)}"#
            return try NativeSecurity.parse(#"{"configApis":[{\#(block)},\#(second)]\#(top)}"#, source: "pinvault_security.json")
        }
        let one = #"{\#(api)}]}"#
        let both = #"{\#(api)},{"id":"second","url":"https://h2.example/"}]}"#
        assertRefused(one, try two(), "config.configApis", "'second'", "runs every Config API its native file declares", #""optional": true"#)
        assertRefused(#"{"configApis":[]}"#, try two(), "'default', 'second'")
        assertRefused(#"{"deviceAlias":"x"}"#, try two(), "'default', 'second'")
        XCTAssertEqual(Set(try parse(both, try two()).config.configApis.keys), ["default", "second"])
        // A debug build, and a release build without a native file, take the config as it comes.
        XCTAssertEqual(Set(try parse(one, try two(), release: false).config.configApis.keys), ["default"])
        XCTAssertNoThrow(try parse(#"{"configApis":[{\#(block)}]}"#, nil))
        // The file may let the app start without a block ...
        let optional = try two(#","optional":true"#)
        XCTAssertEqual(Set(try parse(one, optional).config.configApis.keys), ["default"])
        XCTAssertNoThrow(try parse(both, optional))
        // ... but not the other one,
        assertRefused(#"{"configApis":[{"id":"second","url":"https://h2.example/"}]}"#, optional, "'default'")
        // and not with managed trust roots: the missing block's hosts would fall back to the roots.
        let roots = try two(#","optional":true"#, top: #","require":{"managedTrustRoots":true}"#)
        assertRefused(one, roots, "'second'", "managedTrustRoots", "cannot be left out")
        XCTAssertNoThrow(try parse(both, roots))
        // A file with static pins only declares no block to run.
        let pins = #"{"pins":[{"hostname":"s.example","sha256":["\#(pinA)","\#(pinB)"]}]}"#
        XCTAssertNoThrow(try parse(#"{"staticPins":\#(pins)}"#, try NativeSecurity.parse(#"{"staticPins":\#(pins)}"#, source: "pinvault_security.json")))
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
