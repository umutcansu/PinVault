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

    // Review 2026-11-14 (K1): a bare entry used to leave the three fields to the bundle.
    func testAVaultFieldTheNativeEntryLeavesOutIsTheLibraryDefaultInAReleaseBuildNeverTheDartValue() throws {
        let bare = try file(top: #","vaultFiles":[{"key":"doc"}]"#)
        func doc(_ extra: String) -> String { #"{\#(api)}],"vaultFiles":[{"key":"doc","endpoint":"api/v1/vault/doc"\#(extra)}]}"# }
        assertRefused(doc(#","signaturePublicKey":"\#(key)""#), native: bare, "vaultFiles[0].signaturePublicKey", "does not give signaturePublicKey", "only from there")
        assertRefused(doc(#","encryption":"PLAIN""#), native: bare, "vaultFiles[0].encryption", "does not give encryption", "only from there")
        assertRefused(doc(#","userAuth":"NONE""#), native: bare, "vaultFiles[0].userAuth", "does not give userAuth", "only from there")
        assertRefused(doc(#","encryption":"USER_AUTH","userAuth":"REQUIRED""#), native: bare, "does not give")
        // Nothing from Dart: the library's defaults (the block's signing keys, PLAIN, NONE).
        let vault = try XCTUnwrap(try parse(doc(""), native: bare).config.vaultFiles["doc"])
        XCTAssertNil(vault.signaturePublicKey)
        XCTAssertEqual(vault.encryption, VaultFileEncryption.plain)
        XCTAssertEqual(vault.userAuth, UserAuth.none)
        // What the entry gives is the value; Dart may repeat it.
        let full = try file(top: #","vaultFiles":[{"key":"doc","signaturePublicKey":"\#(key)","encryption":"USER_AUTH","userAuth":"REQUIRED"}]"#)
        let locked = try XCTUnwrap(try parse(doc(#","encryption":"USER_AUTH""#), native: full).config.vaultFiles["doc"])
        XCTAssertEqual(locked.signaturePublicKey, key)
        XCTAssertEqual(locked.userAuth, UserAuth.required)
        // An entry that gives one field leaves the other two at the default, not to Dart.
        let keyOnly = try file(top: #","vaultFiles":[{"key":"doc","signaturePublicKey":"\#(key)"}]"#)
        assertRefused(doc(#","userAuth":"IF_SCREEN_LOCK""#), native: keyOnly, "does not give userAuth")
        // A debug build, and a release build without a native file, take them from Dart as before.
        let debug = try XCTUnwrap(try parse(doc(#","encryption":"USER_AUTH","userAuth":"REQUIRED""#), native: bare, release: false).config.vaultFiles["doc"])
        XCTAssertEqual(debug.userAuth, UserAuth.required)
        XCTAssertNoThrow(try parse(#"{"configApis":[{\#(block)}],"vaultFiles":[{"key":"doc","endpoint":"api/v1/vault/doc","userAuth":"IF_SCREEN_LOCK"}]}"#, native: nil))
    }

    func testANativeVaultEntryCanFixTheFilesConfigApiEndpointAndAccessPolicy() throws {
        let fixed = try file(top: #","vaultFiles":[{"key":"doc","configApi":"default","endpoint":"api/v1/vault/doc","accessPolicy":"TOKEN"}]"#)
        func doc(_ fields: String) -> String { #"{\#(api)}],"vaultFiles":[{"key":"doc"\#(fields)}]}"# }
        // Dart may leave them out or repeat them.
        let vault = try XCTUnwrap(try parse(doc(""), native: fixed).config.vaultFiles["doc"])
        XCTAssertEqual(vault.endpoint, "api/v1/vault/doc")
        XCTAssertEqual(vault.configApiId, "default")
        XCTAssertEqual(vault.accessPolicy, VaultFileAccessPolicy.token)
        XCTAssertNotNil(vault.accessTokenProvider)
        XCTAssertNoThrow(try parse(doc(#","endpoint":"api/v1/vault/doc","configApi":"default","accessPolicy":"TOKEN""#), native: fixed))
        // A different value is refused, in a debug build too.
        assertRefused(doc(#","endpoint":"api/v1/vault/other""#), native: fixed, "vaultFiles[0].endpoint", "native value is fixed")
        assertRefused(doc(#","configApi":"other""#), native: fixed, "vaultFiles[0].configApi", "native value is fixed")
        assertRefused(doc(#","accessPolicy":"PUBLIC""#), native: fixed, "vaultFiles[0].accessPolicy", "native value is fixed")
        assertRefused(doc(#","accessPolicy":"PUBLIC""#), native: fixed, release: false, "vaultFiles[0].accessPolicy", "native value is fixed")
        // An entry that does not give them leaves them to Dart, as before.
        let bare = try file(top: #","vaultFiles":[{"key":"doc"}]"#)
        XCTAssertEqual(try parse(doc(#","endpoint":"elsewhere/doc","accessPolicy":"TOKEN""#), native: bare).config.vaultFiles["doc"]?.endpoint, "elsewhere/doc")
        assertRefused(doc(""), native: bare, "vaultFiles[0].endpoint", "required")
        // The file's endpoint follows the endpoint rule too.
        XCTAssertThrowsError(try file(top: #","vaultFiles":[{"key":"doc","endpoint":"../admin"}]"#)) { error in
            XCTAssertTrue(((error as? BridgeInputError)?.message ?? "").contains("'..' path segment"), "\(error)")
        }
    }

    // Review 2026-11-17: an entry without configApi let Dart pick the block that serves AND
    // vouches for the file (its signing keys verify a file without its own signature key).
    func testWithTwoNativeBlocksDartCannotPickAVaultFilesConfigApiTheEntryLeavesOut() throws {
        let second = #"{"id":"second","url":"https://h2.example/","bootstrapPins":[{"hostname":"h2.example","sha256":["\#(pinA)","\#(pinB)"]}],"signaturePublicKeys":["\#(key)"]}"#
        func two(_ vault: String) throws -> NativeSecurity {
            try NativeSecurity.parse(#"{"configApis":[{\#(block)},\#(second)],"vaultFiles":[\#(vault)]}"#, source: "pinvault_security.json")
        }
        func doc(_ fields: String) -> String {
            #"{\#(api)},{"id":"second","url":"https://h2.example/"}],"vaultFiles":[{"key":"doc","endpoint":"api/v1/vault/doc"\#(fields)}]}"#
        }
        let bare = try two(#"{"key":"doc"}"#)
        assertRefused(doc(#","configApi":"second""#), native: bare, "vaultFiles[0].configApi", "does not give configApi", "more than one Config API",
                      "only from there", "declare it in that file's vaultFiles entry")
        // The default block (what an absent value resolves to) may be repeated, or left out.
        XCTAssertEqual(try parse(doc(#","configApi":"default""#), native: bare).config.vaultFiles["doc"]?.configApiId, "default")
        XCTAssertEqual(try parse(doc(""), native: bare).config.vaultFiles["doc"]?.configApiId, "default")
        // An entry that gives it: the entry's value, Dart may repeat it, a different one is refused.
        let fixed = try two(#"{"key":"doc","configApi":"second"}"#)
        XCTAssertEqual(try parse(doc(""), native: fixed).config.vaultFiles["doc"]?.configApiId, "second")
        XCTAssertEqual(try parse(doc(#","configApi":"second""#), native: fixed).config.vaultFiles["doc"]?.configApiId, "second")
        assertRefused(doc(#","configApi":"default""#), native: fixed, "vaultFiles[0].configApi", "native value is fixed")
        // A debug build takes Dart's value as before.
        XCTAssertEqual(try parse(doc(#","configApi":"second""#), native: bare, release: false).config.vaultFiles["doc"]?.configApiId, "second")
        // One native block: nothing to choose between, Dart may name it.
        let only = try NativeSecurity.parse(
            #"{"configApis":[{"id":"main","url":"https://h.example:8081/","bootstrapPins":[{"hostname":"h.example","sha256":["\#(pinA)","\#(pinB)"]}],"signaturePublicKeys":["\#(key)"]}],"vaultFiles":[{"key":"doc"}]}"#,
            source: "pinvault_security.json")
        let main = #"{"configApis":[{"id":"main","url":"https://h.example:8081/"}],"vaultFiles":[{"key":"doc","endpoint":"api/v1/vault/doc","configApi":"main"}]}"#
        XCTAssertEqual(try parse(main, native: only).config.vaultFiles["doc"]?.configApiId, "main")
    }

    // Review 2026-11-14 (K2): narrowing wantPinsFor took a pinned host's pins out of the signed
    // view; with managed trust roots that host is then accepted through the roots.
    func testWithManagedTrustRootsAReleaseBuildTakesWantPinsForFromTheFileOnly() throws {
        let roots = #","require":{"managedTrustRoots":true}"#
        let narrowed = #"{\#(api),"wantPinsFor":["cdn.example"]}]}"#
        assertRefused(narrowed, native: try file(top: roots), "configApis[0].wantPinsFor", "managed trust roots", "only from there")
        // None in the file = every host's pins.
        XCTAssertEqual(try parse(#"{\#(api)}]}"#, native: try file(top: roots)).config.configApis["default"]?.wantPinsFor, [])
        // The file's list is the value; Dart may leave it out or repeat it (any order, any case), not change it.
        let declared = try file(#","wantPinsFor":["api.example","cdn.example"]"#, top: roots)
        XCTAssertEqual(try parse(#"{\#(api)}]}"#, native: declared).config.configApis["default"]?.wantPinsFor, ["api.example", "cdn.example"])
        XCTAssertNoThrow(try parse(#"{\#(api),"wantPinsFor":["CDN.example","api.example"]}]}"#, native: declared))
        assertRefused(narrowed, native: declared, "configApis[0].wantPinsFor", "native value is fixed")
        // Without managed roots: Dart's list as before, unless the file gives one.
        XCTAssertEqual(try parse(narrowed, native: try file()).config.configApis["default"]?.wantPinsFor, ["cdn.example"])
        assertRefused(narrowed, native: try file(#","wantPinsFor":["api.example"]"#), "configApis[0].wantPinsFor", "native value is fixed")
        // A debug build takes Dart's list with managed roots on.
        XCTAssertNoThrow(try parse(narrowed, native: try file(top: roots), release: false))
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
        assertRefused(one, native: try two(), "config.configApis", "'second'", "runs every Config API its native file declares", #""optional": true"#)
        assertRefused(#"{"configApis":[]}"#, native: try two(), "'default', 'second'")
        assertRefused(#"{"deviceAlias":"x"}"#, native: try two(), "'default', 'second'")
        XCTAssertEqual(Set(try parse(both, native: try two()).config.configApis.keys), ["default", "second"])
        // A debug build, and a release build without a native file, take the config as it comes.
        XCTAssertEqual(Set(try parse(one, native: try two(), release: false).config.configApis.keys), ["default"])
        XCTAssertNoThrow(try parse(#"{"configApis":[{\#(block)}]}"#, native: nil))
        // The file may let the app start without a block ...
        let optional = try two(#","optional":true"#)
        XCTAssertEqual(Set(try parse(one, native: optional).config.configApis.keys), ["default"])
        XCTAssertNoThrow(try parse(both, native: optional))
        // ... but not the other one,
        assertRefused(#"{"configApis":[{"id":"second","url":"https://h2.example/"}]}"#, native: optional, "'default'")
        // and not with managed trust roots: the missing block's hosts would fall back to the roots.
        let roots = try two(#","optional":true"#, top: #","require":{"managedTrustRoots":true}"#)
        assertRefused(one, native: roots, "'second'", "managedTrustRoots", "cannot be left out")
        XCTAssertNoThrow(try parse(both, native: roots))
        // A file with static pins only declares no block to run.
        let pins = #"{"pins":[{"hostname":"s.example","sha256":["\#(pinA)","\#(pinB)"]}]}"#
        XCTAssertNoThrow(try parse(#"{"staticPins":\#(pins)}"#, native: try NativeSecurity.parse(#"{"staticPins":\#(pins)}"#, source: "pinvault_security.json")))
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
