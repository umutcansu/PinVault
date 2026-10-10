import XCTest
import PinVault
@testable import PinVaultFlutterCore

/// The native security file, deep-nesting refusal and the guard's asynchronous
/// wait.
final class SecurityAndNetworkingTests: XCTestCase {
    let key = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEktplZyI6Mtuhuih3wbgVRAWKarJhn8pm3YaUa4QxaBHfwEbuSrXOpoMG6PjwYcwjpfmArLr1fk1Rsn9H6lh6EQ=="
    let key2 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2B2nCnNnOqLbd9HnN0Bzh1n0yA0V1Z2tKm8bq6H1Z0lFv8yP0n0n8y0Ue7c3Hn2c9mQ3M6nYk0fJm5X3Qh9g=="
    let key3 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEp9Vq4Xn1m3Lk2h8Gf5Jd6Sa0Qw7Er1Ty2Ui3Op4As5Df6Gh7Jk8Lz9Xc0Vb1Nm2Qa3Ws4Ed5Rf6Tg7Yh8Uj9Ik0Ol=="
    let pinA = "x4qg2Ca8dUOIfMYEGlR50p4ygjFpJb7emumz/ppRMSI="
    let pinB = "609TJ66QBh0UWFLa4K85gbE/n8A3FGbboV5YlwWP3G8="
    let evil = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    let tokens = VaultTokenStore()

    lazy var file: NativeSecurity = try! NativeSecurity.parse("""
        {"configApis":[{"id":"default","bootstrapPins":[{"hostname":"h.example","sha256":["\(pinA)","\(pinB)"]}],
          "signaturePublicKeys":["\(key)","\(key2)"],"requiredSignatures":2,"recoveryPublicKeys":["\(key3)"],
          "serverScope":"default-tls","clientCaPins":["\(pinA)"]}]}
        """, source: "pinvault_security.json")

    func parse(_ json: String, native: NativeSecurity?, release: Bool = true, noFileAllowed: Bool = false) throws -> ParsedConfig {
        try ConfigParser.parse(json, tokens: tokens, guardFactory: { _ in ClosureEnvironmentGuard { _ in true } },
                               listener: nil, native: native, release: release, noFileAllowed: noFileAllowed)
    }

    func assertRefused(_ json: String, native: NativeSecurity?, release: Bool = true, noFileAllowed: Bool = false, _ fragments: String...,
                       file: StaticString = #filePath, line: UInt = #line) {
        do {
            _ = try parse(json, native: native, release: release, noFileAllowed: noFileAllowed)
            XCTFail("accepted: \(json.prefix(200))", file: file, line: line)
        } catch {
            let message = (error as? BridgeInputError)?.message ?? (error as? PinVaultError)?.message ?? "\(error)"
            for f in fragments { XCTAssertTrue(message.contains(f), "'\(message)' lacks '\(f)'", file: file, line: line) }
        }
    }

    let base = #""id":"default","url":"https://h.example:8081/""#

    // MARK: native security file

    func testTheNativeValuesApplyAndMayBeRepeated() throws {
        let p = try parse(#"{"configApis":[{\#(base)}]}"#, native: file)
        XCTAssertTrue(p.nativeSecurityApplied)
        let block = try XCTUnwrap(p.config.configApis["default"])
        XCTAssertEqual(block.bootstrapPins.first?.sha256, [pinA, pinB])
        XCTAssertEqual(block.serverScope, "default-tls")
        XCTAssertEqual(block.requiredSignatures, 2)
        _ = try parse("""
            {"configApis":[{\(base),"bootstrapPins":[{"hostname":"H.example","sha256":["\(pinB)","\(pinA)"]}],
              "signaturePublicKeys":["\(key2)","\(key)"],"serverScope":"default-tls"}]}
            """, native: file)
    }

    func testADifferingTrustAnchorIsRefused() {
        assertRefused(#"{"configApis":[{\#(base),"bootstrapPins":[{"hostname":"h.example","sha256":["\#(pinA)","\#(evil)"]}]}]}"#,
                      native: file, "config.configApis[0].bootstrapPins", "fixed")
        assertRefused(#"{"configApis":[{\#(base),"signaturePublicKey":"\#(key)"}]}"#, native: file, "signaturePublicKey")
        assertRefused(#"{"configApis":[{\#(base),"requiredSignatures":1}]}"#, native: file, "requiredSignatures")
        assertRefused(#"{"configApis":[{\#(base),"serverScope":"x"}]}"#, native: file, "serverScope")
        assertRefused(#"{"configApis":[{\#(base),"clientCaPins":["\#(evil)"]}]}"#, native: file, "clientCaPins")
        assertRefused(#"{"configApis":[{\#(base),"recoveryPublicKeys":["\#(key)"]}]}"#, native: file, "recoveryPublicKeys")
    }

    func testUndeclaredBlocksStaticPinsAndRelaxationsAreRefused() {
        assertRefused(#"{"configApis":[{"id":"evil","url":"https://e/","signaturePublicKey":"\#(key)","bootstrapPins":[{"hostname":"e","sha256":["\#(pinA)","\#(pinB)"]}]}]}"#,
                      native: file, "'evil' is not declared")
        assertRefused(#"{"staticPins":{"pins":[{"hostname":"x","sha256":["\#(pinA)","\#(pinB)"]}]}}"#, native: file, "config.staticPins")
        assertRefused(#"{"configApis":[{\#(base),"allowUnsigned":true}]}"#, native: file, release: false, "does not allow")
        assertRefused(#"{"configApis":[{\#(base),"allowUnpinnedConfigApi":true}]}"#, native: file, "allowUnpinnedConfigApi")
        assertRefused(#"{"configApis":[{\#(base),"allowServerGeneratedKey":true}]}"#, native: file, "allowServerGeneratedKey")
    }

    func testWithoutAFileReleaseRefusesDartAnchorsUnlessThePlistAcceptsThem() throws {
        let api = #""id":"a","url":"https://h/","bootstrapPins":[{"hostname":"h","sha256":["\#(pinA)","\#(pinB)"]}],"signaturePublicKey":"\#(key)""#
        assertRefused(#"{"configApis":[{\#(api)}]}"#, native: nil, "none is shipped", NativeSecurity.noFileInfoKey)
        assertRefused(#"{"staticPins":{"pins":[{"hostname":"x","sha256":["\#(pinA)","\#(pinB)"]}]}}"#, native: nil, "none is shipped")
        let accepted = try parse(#"{"configApis":[{\#(api)}]}"#, native: nil, noFileAllowed: true)
        XCTAssertFalse(accepted.nativeSecurityApplied)
    }

    func testWithoutAFileReleaseRefusesTheRelaxationsDebugTakesThem() throws {
        let api = #""id":"a","url":"https://h/","bootstrapPins":[{"hostname":"h","sha256":["\#(pinA)","\#(pinB)"]}],"signaturePublicKey":"\#(key)""#
        assertRefused(#"{"configApis":[{\#(api),"allowServerGeneratedKey":true}]}"#, native: nil, noFileAllowed: true, "refused from Dart", "native security file")
        assertRefused(#"{"configApis":[{"id":"a","url":"https://h/","allowUnsigned":true}]}"#, native: nil, noFileAllowed: true, "allowUnsigned")
        let debug = try parse(#"{"configApis":[{\#(api),"allowServerGeneratedKey":true}]}"#, native: nil, release: false)
        XCTAssertEqual(debug.config.configApis["a"]?.allowServerGeneratedKey, true)
    }

    func testAFileAllowingARelaxationAppliesIt() throws {
        let allowing = try NativeSecurity.parse("""
            {"configApis":[{"id":"default","allowServerGeneratedKey":true,"signaturePublicKeys":["\(key)"],
              "bootstrapPins":[{"hostname":"h","sha256":["\(pinA)","\(pinB)"]}]}]}
            """, source: "f")
        let p = try parse(#"{"configApis":[{\#(base),"bootstrapPins":[{"hostname":"h","sha256":["\#(pinA)","\#(pinB)"]}],"signaturePublicKey":"\#(key)"}]}"#,
                          native: allowing)
        XCTAssertEqual(p.config.configApis["default"]?.allowServerGeneratedKey, true)
    }

    func testAReleaseBuildNeedsTheAnchorsInTheFileAndTheIdentityHostsAreItsCall() throws {
        // A block that only names itself would leave pins and keys to the bundle.
        let bare = try NativeSecurity.parse(#"{"configApis":[{"id":"default"}]}"#, source: "f")
        let anchored = #"\#(base),"bootstrapPins":[{"hostname":"h.example","sha256":["\#(pinA)","\#(pinB)"]}],"signaturePublicKey":"\#(key)""#
        assertRefused(#"{"configApis":[{\#(anchored)}]}"#, native: bare, "bootstrapPins", "declare bootstrapPins")
        let keyless = try NativeSecurity.parse(#"{"configApis":[{"id":"default","bootstrapPins":[{"hostname":"h.example","sha256":["\#(pinA)","\#(pinB)"]}]}]}"#, source: "f")
        assertRefused(#"{"configApis":[{\#(anchored)}]}"#, native: keyless, "signaturePublicKeys", "declare signaturePublicKeys")
        // The relaxations stand in for the anchor they relax; a debug build takes the bare block.
        let relaxed = try NativeSecurity.parse(#"{"configApis":[{"id":"default","allowUnpinnedConfigApi":true,"allowUnsigned":true}]}"#, source: "f")
        XCTAssertNotNil(try parse(#"{"configApis":[{\#(base)}]}"#, native: relaxed))
        XCTAssertNotNil(try parse(#"{"configApis":[{\#(anchored)}]}"#, native: bare, release: false))
        // Who gets the identity: from Dart only where the file names the hosts, or in a debug build.
        assertRefused(#"{"configApis":[{\#(base),"clientCertHosts":["cdn.example:443"]}]}"#, native: file, "clientCertHosts", "declare clientCertHosts")
        XCTAssertNotNil(try parse(#"{"configApis":[{\#(base),"clientCertHosts":["cdn.example:443"]}]}"#, native: file, release: false))
        let naming = try NativeSecurity.parse("""
            {"configApis":[{"id":"default","clientCertHosts":["api.example:443"],
              "bootstrapPins":[{"hostname":"h.example","sha256":["\(pinA)","\(pinB)"]}],"signaturePublicKeys":["\(key)"]}]}
            """, source: "f")
        XCTAssertNotNil(try parse(#"{"configApis":[{\#(base),"clientCertHosts":["API.example:443"]}]}"#, native: naming))
        assertRefused(#"{"configApis":[{\#(base),"clientCertHosts":["cdn.example:443"]}]}"#, native: naming, "clientCertHosts", "fixed")
    }

    func testRequireOnlyTightensAndFixesTheIds() throws {
        let strict = try NativeSecurity.parse("""
            {"configApis":[{"id":"default","url":"https://h.example:8081/","attestation":true,"tokenHosts":["api.example"],
              "bootstrapPins":[{"hostname":"h.example","sha256":["\(pinA)","\(pinB)"]}],"signaturePublicKeys":["\(key)"]}],
             "require":{"requireUnlockedDevice":true,"requireHardwareBackedKeys":true,"requireCaTrust":["h.example"],
                        "expectedBundleIds":["com.example.app"],"expiredConfigGraceSeconds":3600}}
            """, source: "f")
        let p = try parse(#"{"configApis":[{\#(base)}],"requireUnlockedDevice":false,"requireCaTrust":["other.example"]}"#, native: strict)
        XCTAssertTrue(p.config.requireUnlockedDevice, "Dart false does not switch it off")
        XCTAssertTrue(p.config.requireHardwareBackedKeys)
        XCTAssertEqual(Set(p.config.caTrustHosts), ["other.example", "h.example"])
        XCTAssertEqual(p.config.expectedBundleIds, ["com.example.app"])
        XCTAssertEqual(p.config.configApis["default"]?.attestationEnabled, true)
        assertRefused(#"{"configApis":[{\#(base),"attestation":false}]}"#, native: strict, "attestation", "cannot turn it off")
        assertRefused(#"{"configApis":[{\#(base),"tokenHosts":["evil.example"]}]}"#, native: strict, "tokenHosts", "fixed")
        assertRefused(#"{"configApis":[{"id":"default","url":"https://evil.example/"}]}"#, native: strict, "url", "fixed")
        assertRefused(#"{"configApis":[{\#(base)}],"ios":{"expectedBundleIds":["com.evil"]}}"#, native: strict, "expectedBundleIds", "fixed")
        assertRefused(#"{"configApis":[{\#(base)}],"expiredConfigGrace":{"amount":2,"unit":"HOURS"}}"#, native: strict, "expiredConfigGrace")
        _ = try parse(#"{"configApis":[{\#(base)}],"expiredConfigGrace":{"amount":30,"unit":"MINUTES"}}"#, native: strict)
    }

    func testProofOfPossessionFromTheFileCannotBeTurnedOffAndDartMayTurnItOn() throws {
        let proving = try NativeSecurity.parse("""
            {"configApis":[{"id":"default","attestation":true,"proofOfPossession":true,
              "bootstrapPins":[{"hostname":"h.example","sha256":["\(pinA)","\(pinB)"]}],"signaturePublicKeys":["\(key)"]}]}
            """, source: "f")
        XCTAssertEqual(try parse(#"{"configApis":[{\#(base)}]}"#, native: proving).config.configApis["default"]?.tokenProof, true)
        assertRefused(#"{"configApis":[{\#(base),"proofOfPossession":false}]}"#, native: proving, "proofOfPossession", "cannot turn it off")
        let plain = try NativeSecurity.parse("""
            {"configApis":[{"id":"default","bootstrapPins":[{"hostname":"h.example","sha256":["\(pinA)","\(pinB)"]}],"signaturePublicKeys":["\(key)"]}]}
            """, source: "f")
        XCTAssertEqual(try parse(#"{"configApis":[{\#(base),"attestation":true,"proofOfPossession":true}]}"#, native: plain).config.configApis["default"]?.tokenProof, true)
        XCTAssertEqual(try parse(#"{"configApis":[{\#(base),"attestation":true}]}"#, native: plain).config.configApis["default"]?.tokenProof, false)
    }

    func testOfflineAgesUrlsAndTheLockStrengthCannotBeLoosened() throws {
        let strict = try NativeSecurity.parse("""
            {"configApis":[{"id":"default","bootstrapPins":[{"hostname":"h.example","sha256":["\(pinA)","\(pinB)"]}],"signaturePublicKeys":["\(key)"],
              "enrollmentUrl":"https://enroll.example/"}],
             "require":{"vaultFileMaxOfflineAgeSeconds":3600,"userAuthStrength":"BIOMETRIC_CURRENT_SET"},
             "vaultFiles":[{"key":"statement","maxOfflineAgeSeconds":600}]}
            """, source: "f")
        let p = try parse(#"{"configApis":[{\#(base)}],"vaultFiles":[{"key":"statement","endpoint":"e"}]}"#, native: strict)
        XCTAssertEqual(p.config.vaultFileMaxOfflineAgeMs, 3_600_000, "the file's value when Dart sets none")
        XCTAssertEqual(p.config.vaultFiles["statement"]?.maxOfflineAgeMs, 600_000)
        XCTAssertEqual(p.config.userAuthStrength, .biometricCurrentSet)
        assertRefused(#"{"configApis":[{\#(base)}],"vaultFileMaxOfflineAge":{"amount":2,"unit":"HOURS"}}"#, native: strict, "vaultFileMaxOfflineAge")
        assertRefused(#"{"configApis":[{\#(base)}],"vaultFileMaxOfflineAge":{"amount":0,"unit":"SECONDS"}}"#, native: strict, "vaultFileMaxOfflineAge")
        assertRefused(#"{"configApis":[{\#(base)}],"vaultFiles":[{"key":"statement","endpoint":"e","maxOfflineAge":{"amount":1,"unit":"DAYS"}}]}"#, native: strict, "maxOfflineAge")
        assertRefused(#"{"configApis":[{\#(base)}],"ios":{"userAuthStrength":"DEVICE_OWNER"}}"#, native: strict, "userAuthStrength", "fixed")
        assertRefused(#"{"configApis":[{\#(base),"enrollmentUrl":"https://evil.example/"}]}"#, native: strict, "enrollmentUrl", "fixed")
        _ = try parse(#"{"configApis":[{\#(base)}],"vaultFileMaxOfflineAge":{"amount":30,"unit":"MINUTES"}}"#, native: strict)
        // The config-wide cap holds for a file the file does not name a cap for, too.
        let globalOnly = try NativeSecurity.parse("""
            {"configApis":[{"id":"default","bootstrapPins":[{"hostname":"h.example","sha256":["\(pinA)","\(pinB)"]}],"signaturePublicKeys":["\(key)"]}],
             "require":{"vaultFileMaxOfflineAgeSeconds":3600}}
            """, source: "f")
        assertRefused(#"{"configApis":[{\#(base)}],"vaultFiles":[{"key":"any","endpoint":"e","maxOfflineAge":{"amount":0,"unit":"SECONDS"}}]}"#, native: globalOnly, "maxOfflineAge")
        assertRefused(#"{"configApis":[{\#(base)}],"vaultFiles":[{"key":"any","endpoint":"e","maxOfflineAge":{"amount":2,"unit":"HOURS"}}]}"#, native: globalOnly, "maxOfflineAge")
        _ = try parse(#"{"configApis":[{\#(base)}],"vaultFiles":[{"key":"any","endpoint":"e","maxOfflineAge":{"amount":10,"unit":"MINUTES"}}]}"#, native: globalOnly)
    }

    func testAnEmptyConfigApiListNeedsNoFile() {
        XCTAssertThrowsError(try parse(#"{"configApis":[]}"#, native: nil)) { error in
            XCTAssertFalse(((error as? BridgeInputError)?.message ?? "\(error)").contains("none is shipped"), "nothing to anchor")
        }
    }

    func testAReleaseBuildCapsTheExpiredConfigGrace() {
        assertRefused(#"{"deviceAlias":"x","expiredConfigGrace":{"amount":8,"unit":"DAYS"}}"#, native: nil, "at most 7 days")
    }

    func testDeclaredVaultFilesKeepTheirProtection() throws {
        let files = try NativeSecurity.parse("""
            {"configApis":[{"id":"default","bootstrapPins":[{"hostname":"h.example","sha256":["\(pinA)","\(pinB)"]}],"signaturePublicKeys":["\(key)"]}],
             "vaultFiles":[{"key":"statement","signaturePublicKey":"\(key)","encryption":"USER_AUTH","userAuth":"REQUIRED"}]}
            """, source: "f")
        let ok = try parse(#"{"configApis":[{\#(base)}],"vaultFiles":[{"key":"statement","endpoint":"api/v1/vault/statement"}]}"#, native: files)
        let file = try XCTUnwrap(ok.config.vaultFiles["statement"])
        XCTAssertEqual(file.encryption, .userAuth)
        XCTAssertEqual(file.userAuth, .required)
        assertRefused(#"{"configApis":[{\#(base)}],"vaultFiles":[{"key":"statement","endpoint":"e","encryption":"PLAIN"}]}"#, native: files, "encryption", "fixed")
        assertRefused(#"{"configApis":[{\#(base)}],"vaultFiles":[{"key":"other","endpoint":"e"}]}"#, native: files, "'other' is not declared")
    }

    func testTheFileIsParsedStrictly() {
        for (text, fragment) in [
            (#"{"configApis":[{"id":"a","serverScop":"x"}]}"#, "'serverScop'"),
            (#"{"configApis":[{"id":"a"},{"id":"a"}]}"#, "declared twice"),
            ("{}", "declares neither"),
            (#"{"configApis":"#, "not valid JSON"),
            (#"{"configApis":[{"id":"a","bootstrapPins":[{"hostname":"h","sha256":["\#(pinA)"]}]}]}"#, "2 pins"),
        ] {
            XCTAssertThrowsError(try NativeSecurity.parse(text, source: "pinvault_security.json")) { error in
                let message = (error as? BridgeInputError)?.message ?? "\(error)"
                XCTAssertTrue(message.hasPrefix("native security file"), message)
                XCTAssertTrue(message.contains(fragment), "'\(message)' lacks '\(fragment)'")
            }
        }
    }

    // MARK: deep nesting

    func testDeepNestingIsRefusedBeforeTheParser() {
        let deep = String(repeating: "[", count: 100_000) + String(repeating: "]", count: 100_000)
        XCTAssertThrowsError(try StrictJSON.parseObject(#"{"a":\#(deep)}"#, path: "config", maxChars: 1 << 20)) { error in
            XCTAssertEqual((error as? BridgeInputError)?.message, "config: nested too deeply")
        }
        XCTAssertEqual(StrictJSON.nestingDepth(#"{"a":"[[[[[[[[[[{{{{"}"#), 1)
        XCTAssertEqual(StrictJSON.nestingDepth(#"{"a":[{"b":"\"]"}]}"#), 3)
    }

    // MARK: guard

    func testAVerdictAskedBeforehandIsAnsweredWithoutWaiting() async throws {
        var g: DartEnvironmentGuard!
        g = DartEnvironmentGuard(timeoutMs: 5000) { id, op in
            DispatchQueue.global().asyncAfter(deadline: .now() + .milliseconds(20)) { g.answer(id, allowed: op == "INIT") }
        }
        let both = try await g.withVerdicts([.start, .enroll]) { [try g.allows(.start), try g.allows(.enroll)] }
        XCTAssertEqual(both, [true, false])
        let timed = try await g.withVerdicts([.start]) { () async throws -> TimeInterval in
            let t = Date()
            _ = try g.allows(.start)
            return Date().timeIntervalSince(t)
        }
        XCTAssertLessThan(timed, 0.01, "the library's check reads the verdict, nothing waits")
        let refused = try await g.withVerdicts([.enroll]) { try g.allows(.enroll) }
        XCTAssertFalse(refused)
        XCTAssertEqual(g.pendingCount, 0)
    }

    func testTheAsyncWaitTimesOutAsARefusal() async {
        let g = DartEnvironmentGuard(timeoutMs: 100) { _, _ in }
        let allowed = await g.verdict(.fetchFile)
        XCTAssertFalse(allowed)
        XCTAssertEqual(g.pendingCount, 0)
    }
}
