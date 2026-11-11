import XCTest
import PinVault
@testable import RNPinVaultCore

/// The other half of ``ConfigFieldPolicyTests`` (the Swift twin of the RN Android
/// bridge's NativeFieldEnforcementTest): a key classified NATIVE must be refused
/// when a release build's JS sets it to something the native file did not say.
/// Every NATIVE key needs an example here (a new one fails until it has one), and
/// every example must be refused — by a message that names the key, so a refusal
/// for another reason does not pass for the rule.
final class NativeFieldEnforcementTests: XCTestCase {
    let key = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEktplZyI6Mtuhuih3wbgVRAWKarJhn8pm3YaUa4QxaBHfwEbuSrXOpoMG6PjwYcwjpfmArLr1fk1Rsn9H6lh6EQ=="
    let key2 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETknGSzvxqzg4sN0QkkTYsqHo2Qa7gLt8u0Bns3Qo9DqWM6PbQIjtemRK/G5Kii4bBCiebDck8WvrO9hm3KZ2og=="
    let pinA = "x4qg2Ca8dUOIfMYEGlR50p4ygjFpJb7emumz/ppRMSI="
    let pinB = "609TJ66QBh0UWFLa4K85gbE/n8A3FGbboV5YlwWP3G8="
    let evil = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    let tokens = VaultTokenStore()

    /// The file: anchors, addresses and one vault file; nothing relaxed, no static pins, no `ios.resolve`.
    func native() throws -> NativeSecurity {
        try NativeSecurity.parse("""
            {"configApis":[{"id":"default","url":"https://h.example:8081/",
              "bootstrapPins":[{"hostname":"h.example","sha256":["\(pinA)","\(pinB)"]}],
              "signaturePublicKeys":["\(key)"],"requiredSignatures":1,"serverScope":"default-tls",
              "enrollmentUrl":"https://h.example:8081/","renewalUrl":"https://h.example:8093/",
              "tokenHosts":["h.example"],"clientCertHosts":["h.example:8092"],"healthEndpoint":"health"}],
             "require":{"requireUnlockedDevice":true},
             "vaultFiles":[{"key":"doc","signaturePublicKey":"\(key)","encryption":"END_TO_END","userAuth":"NONE"}]}
            """, source: "pinvault_security.json")
    }

    var otherPins: String { #"[{"hostname":"h.example","sha256":["\#(evil)","\#(pinB)"]}]"# }
    var staticPins: String { #"{"pins":[{"hostname":"s.example","sha256":["\#(pinA)","\#(pinB)"]}]}"# }

    /// Where the JS fragment goes.
    enum At { case block, root, vault, ios }

    struct Example {
        let at: At
        let fragment: String
        /// What the refusal must name.
        let names: String
    }

    /// One release-build JS value per NATIVE key that the file did not give.
    var examples: [String: Example] {
        var m: [String: Example] = [:]
        func put(_ path: String, _ at: At, _ fragment: String, _ names: String) { m[path] = Example(at: at, fragment: fragment, names: names) }
        let api = "config.configApis[]"
        put("\(api).url", .block, #""url":"https://evil.example/""#, "url")
        put("\(api).enrollmentUrl", .block, #""enrollmentUrl":"https://evil.example/""#, "enrollmentUrl")
        put("\(api).renewalUrl", .block, #""renewalUrl":"https://evil.example/""#, "renewalUrl")
        put("\(api).tokenHosts", .block, #""tokenHosts":["evil.example"]"#, "tokenHosts")
        put("\(api).clientCertHosts", .block, #""clientCertHosts":["evil.example:443"]"#, "clientCertHosts")
        for sub in ["", "[].hostname", "[].sha256", "[].version", "[].forceUpdate", "[].mtls", "[].clientCertVersion"] {
            put("\(api).bootstrapPins\(sub)", .block, #""bootstrapPins":\#(otherPins)"#, "bootstrapPins")
        }
        put("\(api).signaturePublicKey", .block, #""signaturePublicKey":"\#(key2)""#, "signaturePublicKey")
        put("\(api).signaturePublicKeys", .block, #""signaturePublicKeys":["\#(key2)"]"#, "signaturePublicKeys")
        put("\(api).requiredSignatures", .block, #""requiredSignatures":2,"signaturePublicKeys":["\#(key)"]"#, "requiredSignatures")
        put("\(api).recoveryPublicKeys", .block, #""recoveryPublicKeys":["\#(key2)"]"#, "recoveryPublicKeys")
        put("\(api).requiredRecoverySignatures", .block, #""requiredRecoverySignatures":2"#, "requiredRecoverySignatures")
        put("\(api).serverScope", .block, #""serverScope":"other-scope""#, "serverScope")
        put("\(api).clientCaPins", .block, #""clientCaPins":["\#(evil)"]"#, "clientCaPins")
        put("\(api).allowUnsigned", .block, #""allowUnsigned":true"#, "allowUnsigned")
        put("\(api).allowUnpinnedConfigApi", .block, #""allowUnpinnedConfigApi":true"#, "allowUnpinnedConfigApi")
        put("\(api).allowServerGeneratedKey", .block, #""allowServerGeneratedKey":true"#, "allowServerGeneratedKey")
        put("\(api).healthEndpoint", .block, #""healthEndpoint":"api/v1/certificate-config""#, "healthEndpoint")
        put("config.vaultFiles[].signaturePublicKey", .vault, #""signaturePublicKey":"\#(key2)""#, "signaturePublicKey")
        put("config.vaultFiles[].encryption", .vault, #""encryption":"PLAIN""#, "encryption")
        put("config.vaultFiles[].userAuth", .vault, #""userAuth":"REQUIRED""#, "userAuth")
        for sub in ["", ".version", ".forceUpdate", ".pins", ".pins[].hostname", ".pins[].sha256", ".pins[].version",
                    ".pins[].forceUpdate", ".pins[].mtls", ".pins[].clientCertVersion"] {
            put("config.staticPins\(sub)", .root, #""staticPins":\#(staticPins)"#, "staticPins")
        }
        put("config.managedTrustRoots", .root, #""managedTrustRoots":true"#, "managedTrustRoots")
        put("config.requirePinnedReactNativeNetworking", .root, #""requirePinnedReactNativeNetworking":false"#,
            "requirePinnedReactNativeNetworking")
        put("config.ios.requireUnlockedDeviceAllowFallback", .ios, #""requireUnlockedDeviceAllowFallback":true"#,
            "requireUnlockedDeviceAllowFallback")
        put("config.ios.resolve", .ios, #""resolve":{"h.example":"10.0.0.66"}"#, "resolve")
        return m
    }

    func js(_ at: At, _ fragment: String) -> String {
        // A fragment that gives `url` replaces the block's (JSONSerialization keeps the first of two equal keys).
        let url = at == .block && fragment.hasPrefix(#""url":"#) ? "" : #","url":"https://h.example:8081/""#
        let block = #"{"id":"default"\#(url)\#(at == .block ? ",\(fragment)" : "")}"#
        let vault = #"{"key":"doc","endpoint":"api/v1/vault/doc"\#(at == .vault ? ",\(fragment)" : "")}"#
        let ios = at == .ios ? #","ios":{\#(fragment)}"# : ""
        let root = at == .root ? ",\(fragment)" : ""
        return #"{"configApis":[\#(block)],"vaultFiles":[\#(vault)]\#(ios)\#(root)}"#
    }

    @discardableResult
    func parse(_ json: String) throws -> ParsedConfig {
        try ConfigParser.parse(json, tokens: tokens, guardFactory: { _ in ClosureEnvironmentGuard { _ in true } }, listener: nil,
                               native: try native(), release: true, noFileAllowed: false, reactNetworkingEnabled: true)
    }

    func testEveryNativeKeyHasAnExampleAndNoneIsLeftForAKeyThatIsNotNative() {
        let nativeKeys = Set(ConfigFieldPolicy.policy.filter { $0.value == .native }.keys)
        let exampleKeys = Set(examples.keys)
        XCTAssertEqual(nativeKeys.subtracting(exampleKeys).sorted(), [], "NATIVE keys without an example here")
        XCTAssertEqual(exampleKeys.subtracting(nativeKeys).sorted(), [], "examples for keys that are not NATIVE")
    }

    func testTheBaseConfigItselfIsAccepted() throws {
        XCTAssertNoThrow(try parse(js(.root, #""deviceAlias":"x""#)))
    }

    func testAReleaseBuildRefusesEveryNativeKeyTheFileDidNotGive() {
        var accepted: [String] = []
        var otherReason: [String] = []
        for (path, example) in examples.sorted(by: { $0.key < $1.key }) {
            do {
                try parse(js(example.at, example.fragment))
                accepted.append(path)
            } catch {
                let message = (error as? BridgeInputError)?.message ?? (error as? PinVaultError)?.message ?? "\(error)"
                if !message.contains(example.names) { otherReason.append("\(path): \(message)") }
            }
        }
        XCTAssertEqual(accepted, [], "a release build took these NATIVE keys from JS")
        XCTAssertEqual(otherReason, [], "refused, but not for the key itself")
    }
}
