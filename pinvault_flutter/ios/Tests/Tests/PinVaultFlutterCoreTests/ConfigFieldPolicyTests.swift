import XCTest
import PinVault
@testable import PinVaultFlutterCore

/// Review 2026-11-12: a field the parser reads was Dart's to set unless someone
/// remembered to add a release rule for it. Every key `ConfigParser.parse` asks
/// for must now be classified in ``ConfigFieldPolicy`` — a new key without a
/// decision, or a decision for a key no longer read, fails here.
final class ConfigFieldPolicyTests: XCTestCase {
    let key = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEktplZyI6Mtuhuih3wbgVRAWKarJhn8pm3YaUa4QxaBHfwEbuSrXOpoMG6PjwYcwjpfmArLr1fk1Rsn9H6lh6EQ=="
    let pinA = "x4qg2Ca8dUOIfMYEGlR50p4ygjFpJb7emumz/ppRMSI="
    let pinB = "609TJ66QBh0UWFLa4K85gbE/n8A3FGbboV5YlwWP3G8="

    override func tearDown() {
        Fields.readHook = nil
        super.tearDown()
    }

    /// Every nested object present once, so every key path is asked for.
    var everyObject: String {
        """
        {"configApis":[{"id":"default","url":"https://h.example:8081/",
            "bootstrapPins":[{"hostname":"h.example","sha256":["\(pinA)","\(pinB)"]}],
            "signaturePublicKey":"\(key)","attestationInterval":{"amount":10,"unit":"MINUTES"}}],
         "vaultFiles":[{"key":"flags","endpoint":"api/v1/vault/flags","maxOfflineAge":{"amount":1,"unit":"DAYS"}}],
         "staticPins":{"pins":[{"hostname":"s.example","sha256":["\(pinA)","\(pinB)"]}]},
         "expiredConfigGrace":{"amount":0,"unit":"SECONDS"},
         "vaultFileMaxOfflineAge":{"amount":1,"unit":"DAYS"},
         "environmentGuard":{},
         "android":{},
         "ios":{}}
        """
    }

    func keysRead() throws -> Set<String> {
        var read = Set<String>()
        let index = try NSRegularExpression(pattern: #"\[\d+\]"#)
        Fields.readHook = { path, key in
            let p = index.stringByReplacingMatches(in: path, range: NSRange(path.startIndex..., in: path), withTemplate: "[]")
            read.insert("\(p).\(key)")
        }
        defer { Fields.readHook = nil }
        _ = try ConfigParser.parse(everyObject, tokens: VaultTokenStore(),
                                   guardFactory: { _ in ClosureEnvironmentGuard { _ in true } }, listener: nil)
        return read
    }

    func testEveryKeyTheParserReadsHasAReleasePolicyAndEveryPolicyNamesAKeyItReads() throws {
        let read = try keysRead()
        let classified = Set(ConfigFieldPolicy.policy.keys)
        XCTAssertEqual(read.subtracting(classified).sorted(), [], "keys read but not classified in ConfigFieldPolicy.policy")
        XCTAssertEqual(classified.subtracting(read).sorted(), [], "ConfigFieldPolicy.policy names keys the parser no longer reads")
    }
}
