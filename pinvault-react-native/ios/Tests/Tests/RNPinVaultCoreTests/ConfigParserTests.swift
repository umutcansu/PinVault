import XCTest
import PinVault
@testable import RNPinVaultCore

final class ConfigParserTests: XCTestCase {
    let key = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEktplZyI6Mtuhuih3wbgVRAWKarJhn8pm3YaUa4QxaBHfwEbuSrXOpoMG6PjwYcwjpfmArLr1fk1Rsn9H6lh6EQ=="
    let pinA = "x4qg2Ca8dUOIfMYEGlR50p4ygjFpJb7emumz/ppRMSI="
    let pinB = "609TJ66QBh0UWFLa4K85gbE/n8A3FGbboV5YlwWP3G8="
    let tokens = VaultTokenStore()

    func api(_ extra: String = "") -> String {
        #"{"id":"default","url":"https://h.example:8081/","bootstrapPins":[{"hostname":"h.example","sha256":["# +
            #""\#(pinA)","\#(pinB)"]}],"signaturePublicKey":"\#(key)"\#(extra)}"#
    }

    func parse(_ json: String) throws -> ParsedConfig {
        try ConfigParser.parse(json, tokens: tokens, guardFactory: { _ in ClosureEnvironmentGuard { _ in true } }, listener: nil)
    }

    func assertRefused(_ json: String, _ fragments: String..., file: StaticString = #filePath, line: UInt = #line) {
        do {
            _ = try parse(json)
            XCTFail("accepted: \(json.prefix(200))", file: file, line: line)
        } catch {
            let message = (error as? BridgeInputError)?.message ?? (error as? PinVaultError)?.message ?? "\(error)"
            for f in fragments { XCTAssertTrue(message.contains(f), "'\(message)' lacks '\(f)'", file: file, line: line) }
        }
    }

    func testFullConfigGoesThroughTheBuilders() throws {
        let parsed = try parse("""
            {"configApis":[\(api(#","serverScope":"default-tls","attestation":true,"attestationInterval":{"amount":10,"unit":"MINUTES"}"#))],
             "vaultFiles":[{"key":"flags","endpoint":"api/v1/vault/flags"},
               {"key":"secret","endpoint":"api/v1/vault/secret","accessPolicy":"TOKEN_MTLS","encryption":"USER_AUTH",
                "userAuth":"REQUIRED","maxOfflineAge":{"amount":7,"unit":"DAYS"}}],
             "requireCaTrust":["www.example.com"],"updateIntervalMinutes":15,"requireUnlockedDevice":true,
             "environmentGuard":{"timeoutMs":2000},
             "android":{"pinGlobalNetworking":false},
             "ios":{"resolve":{"mock-tls.sample":"10.0.0.1"},"userAuthStrength":"BIOMETRIC_CURRENT_SET"}}
            """)
        let c = parsed.config
        let block = try XCTUnwrap(c.configApis["default"])
        XCTAssertEqual(block.bootstrapPins.first?.sha256, [pinA, pinB])
        XCTAssertTrue(block.attestationEnabled)
        let secret = try XCTUnwrap(c.vaultFiles["secret"])
        XCTAssertEqual(secret.accessPolicy, .tokenMtls)
        XCTAssertEqual(secret.encryption, .userAuth)
        XCTAssertEqual(secret.userAuth, .required)
        XCTAssertEqual(secret.maxOfflineAgeMs, 7 * 86_400_000)
        XCTAssertEqual(c.caTrustHosts, ["www.example.com"])
        XCTAssertEqual(c.updateIntervalMinutes, 15)
        XCTAssertTrue(c.requireUnlockedDevice)
        XCTAssertEqual(c.resolvedHosts["mock-tls.sample"], "10.0.0.1")
        XCTAssertEqual(c.userAuthStrength, .biometricCurrentSet)
        XCTAssertEqual(parsed.guardTimeoutMs, 2000)
        XCTAssertNotNil(c.environmentGuard)
    }

    func testTokenFilesReadTheTokenFromNativeMemory() throws {
        let c = try parse(#"{"configApis":[\#(api())],"vaultFiles":[{"key":"s","endpoint":"e","accessPolicy":"TOKEN"}]}"#).config
        let provider = try XCTUnwrap(c.vaultFiles["s"]?.accessTokenProvider)
        XCTAssertEqual(provider(), "")
        tokens.put("s", "tok-123456")
        XCTAssertEqual(provider(), "tok-123456")
    }

    func testAbsoluteEndpointsAreRefused() {   // RN-2
        assertRefused(#"{"configApis":[\#(api(#","configEndpoint":"https://evil.example/pins""#))]}"#, "configEndpoint", "relative path")
        assertRefused(#"{"configApis":[\#(api(#","clientCertEndpoint":"/abs""#))]}"#, "clientCertEndpoint", "relative path")
        assertRefused(#"{"configApis":[\#(api())],"vaultFiles":[{"key":"k","endpoint":"https://evil.example/f","accessPolicy":"TOKEN"}]}"#, "endpoint", "relative path")
    }

    func testUnknownKeysAreRefused() {
        assertRefused(#"{"configApis":[\#(api())],"confgApis":[]}"#, "config", "'confgApis'")
        assertRefused(#"{"configApis":[\#(api(#","bootstrapPinz":[]"#))]}"#, "config.configApis[0]", "'bootstrapPinz'")
        assertRefused(#"{"configApis":[\#(api())],"vaultFiles":[{"key":"k","endpoint":"e","acessPolicy":"TOKEN"}]}"#, "'acessPolicy'")
        assertRefused(#"{"configApis":[\#(api())],"ios":{"reslove":{}}}"#, "config.ios", "'reslove'")
    }

    func testWrongTypesAreRefusedNeverCoerced() {
        assertRefused(#"{"configApis":[\#(api())],"maxRetryCount":"3"}"#, "maxRetryCount", "number")
        assertRefused(#"{"configApis":[\#(api())],"maxRetryCount":true}"#, "number")
        assertRefused(#"{"configApis":[\#(api())],"maxRetryCount":2.5}"#, "whole number")
        assertRefused(#"{"configApis":[\#(api())],"requireUnlockedDevice":1}"#, "boolean")
        assertRefused(#"{"configApis":[\#(api())],"requireCaTrust":"x"}"#, "list of strings")
        assertRefused(#"{"configApis":[\#(api())],"vaultFiles":[{"key":"k","endpoint":"e","encryption":"user_auth"}]}"#, "USER_AUTH")
        assertRefused("[]", "must be an object")
        assertRefused("{", "not valid JSON")
    }

    func testRangesAndSizesAreBounded() {
        assertRefused(#"{"configApis":[\#(api())],"maxRetryCount":11}"#, "between 0 and 10")
        assertRefused(#"{"configApis":[\#(api())],"environmentGuard":{"timeoutMs":60000}}"#, "timeoutMs")
        assertRefused(#"{"configApis":[\#(api())],"deviceAlias":"a\nb"}"#, "control characters")
        assertRefused(#"{"deviceAlias":"\#(String(repeating: "a", count: StrictJSON.maxInputChars))"}"#, "larger than")
        assertRefused(#"{"configApis":[{"id":"a","url":"http://h/","signaturePublicKey":"k"}]}"#, "https://")
    }

    func testBuilderRulesStillApply() {
        assertRefused(#"{"configApis":[{"id":"a","url":"https://h/","bootstrapPins":[{"hostname":"h","sha256":["\#(pinA)"]}],"signaturePublicKey":"\#(key)"}]}"#, "bootstrapPins[0]")
        assertRefused(#"{"configApis":[\#(api())],"vaultFiles":[{"key":"k","endpoint":"e","encryption":"USER_AUTH"}]}"#, "userAuth")
        assertRefused(#"{"configApis":[\#(api(#","signaturePublicKeys":["k"]"#))]}"#, "not both")
    }

    func testUnlockPrompt() throws {
        let (prompt, encoding) = try ConfigParser.unlockPrompt(#"{"title":"Aç","encoding":"base64"}"#)
        XCTAssertEqual(prompt.title, "Aç")
        XCTAssertEqual(encoding, "base64")
        XCTAssertThrowsError(try ConfigParser.unlockPrompt(#"{"title":"x","encoding":"hex"}"#))
        XCTAssertThrowsError(try ConfigParser.unlockPrompt(#"{"titel":"x"}"#))
    }
}
