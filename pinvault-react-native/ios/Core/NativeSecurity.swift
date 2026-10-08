// The app's native security file (the Swift twin of NativeSecurity.kt): the
// trust anchors and relaxations of `start(config)` declared outside the JS
// bundle, which an OTA update (CodePush, Expo Updates) or an edited bundle can
// change. The file is a resource of the app bundle (`pinvault_security.json`),
// which the code signature seals. Same JSON shape as a JS config subset:
//
//   { "configApis": [{ "id", "bootstrapPins", "signaturePublicKeys", "requiredSignatures",
//                      "recoveryPublicKeys", "requiredRecoverySignatures", "serverScope",
//                      "clientCaPins", "allowUnsigned", "allowUnpinnedConfigApi",
//                      "allowServerGeneratedKey" }],
//     "staticPins": { "pins": [...], "version": 1 } }
//
// When the file is there: every JS Config API (and JS `staticPins`) must be
// declared in it; a declared field is the value (JS may omit or repeat it, a
// different value is refused); the three relaxations need the file's consent.
// Without it, release builds refuse the three relaxations from JS.
import Foundation
import PinVault

public struct NativeSecurity {
    public static let resourceName = "pinvault_security"
    static let maxFileChars = 256 * 1024

    public struct Block {
        let bootstrapPins: [HostPin]?
        let signaturePublicKeys: [String]?
        let requiredSignatures: Int?
        let recoveryPublicKeys: [String]?
        let requiredRecoverySignatures: Int?
        let serverScope: String?
        let clientCaPins: [String]?
        let allowUnsigned: Bool
        let allowUnpinnedConfigApi: Bool
        let allowServerGeneratedKey: Bool
    }

    /// Where the file came from, for messages.
    public let source: String
    let blocks: [String: Block]
    let staticPins: CertificateConfig?

    /// The file from `bundle`; nil when the app ships none. A broken file throws `BridgeInputError`.
    public static func load(from bundle: Bundle = .main) throws -> NativeSecurity? {
        guard let url = bundle.url(forResource: resourceName, withExtension: "json") else { return nil }
        let source = "\(resourceName).json (app bundle)"
        guard let data = try? Data(contentsOf: url) else {
            throw BridgeInputError("native security file \(source): cannot be read")
        }
        guard let text = String(data: data, encoding: .utf8) else {
            throw BridgeInputError("native security file \(source): not UTF-8")
        }
        return try parse(text, source: source)
    }

    public static func parse(_ text: String, source: String) throws -> NativeSecurity {
        do {
            let root = try StrictJSON.parseObject(text, path: source, maxChars: maxFileChars)
            var blocks: [String: Block] = [:]
            for b in try root.objectList("configApis", maxItems: ConfigParser.maxConfigApis) ?? [] {
                let id = try b.requireString("id", maxLength: 128)
                if blocks[id] != nil { throw BridgeInputError("\(b.path).id: '\(id)' is declared twice") }
                blocks[id] = Block(
                    bootstrapPins: try b.objectList("bootstrapPins", maxItems: ConfigParser.maxPins)?.map(ConfigParser.hostPin),
                    signaturePublicKeys: try b.stringList("signaturePublicKeys", maxItems: 16, maxLength: ConfigParser.keyLength, multiline: true),
                    requiredSignatures: try b.int("requiredSignatures", min: 1, max: 16),
                    recoveryPublicKeys: try b.stringList("recoveryPublicKeys", maxItems: 16, maxLength: ConfigParser.keyLength, multiline: true),
                    requiredRecoverySignatures: try b.int("requiredRecoverySignatures", min: 1, max: 16),
                    serverScope: try b.string("serverScope", maxLength: 128),
                    clientCaPins: try b.stringList("clientCaPins", maxItems: 16, maxLength: 128),
                    allowUnsigned: try b.bool("allowUnsigned") == true,
                    allowUnpinnedConfigApi: try b.bool("allowUnpinnedConfigApi") == true,
                    allowServerGeneratedKey: try b.bool("allowServerGeneratedKey") == true
                )
                try b.finish()
            }
            let staticPins = try root.object("staticPins").map(ConfigParser.staticPins)
            try root.finish()
            if blocks.isEmpty && staticPins == nil {
                throw BridgeInputError("\(source): declares neither configApis nor staticPins")
            }
            return NativeSecurity(source: source, blocks: blocks, staticPins: staticPins)
        } catch let e as BridgeInputError {
            throw e.message.hasPrefix("native security file") ? e : BridgeInputError("native security file \(e.message)")
        } catch {
            throw BridgeInputError("native security file \(source): \((error as? PinVaultError)?.message ?? "\(error)")")
        }
    }

    // MARK: comparison (the order of lists does not matter)

    static func sameKeys(_ a: [String], _ b: [String]) -> Bool {
        Set(a.map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }) == Set(b.map { $0.trimmingCharacters(in: .whitespacesAndNewlines) })
    }

    private static func pinKey(_ p: HostPin) -> String {
        [p.hostname.lowercased(), p.sha256.sorted().joined(separator: ","), "\(p.version)", "\(p.forceUpdate)", "\(p.mtls)",
         p.clientCertVersion.map { "\($0)" } ?? "nil"].joined(separator: "|")
    }

    static func samePins(_ a: [HostPin], _ b: [HostPin]) -> Bool {
        a.map(pinKey).sorted() == b.map(pinKey).sorted()
    }

    static func sameStaticPins(_ a: CertificateConfig, _ b: CertificateConfig) -> Bool {
        a.version == b.version && a.forceUpdate == b.forceUpdate && samePins(a.pins, b.pins)
    }
}

/// What JS asked for in one `configApis[i]` entry, before the native policy.
struct SecurityFields {
    var bootstrapPins: [HostPin]?
    var oneKey: String?
    var keys: [String]?
    var requiredSignatures: Int?
    var recoveryKeys: [String]?
    var requiredRecovery: Int?
    var serverScope: String?
    var clientCaPins: [String]?
    var allowUnsigned: Bool
    var allowUnpinned: Bool
    var allowServerKey: Bool
}

enum SecurityPolicy {
    static let relaxationsHint =
        "a release build takes it only from the app's native security file (\(NativeSecurity.resourceName).json, README \"Native security file\")"

    static func apply(path: String, id: String, js: SecurityFields, native: NativeSecurity?, release: Bool) throws -> SecurityFields {
        guard let native else {
            if release {
                if js.allowUnsigned { throw BridgeInputError("\(path).allowUnsigned: refused from JS; \(relaxationsHint)") }
                if js.allowUnpinned { throw BridgeInputError("\(path).allowUnpinnedConfigApi: refused from JS; \(relaxationsHint)") }
                if js.allowServerKey { throw BridgeInputError("\(path).allowServerGeneratedKey: refused from JS; \(relaxationsHint)") }
            }
            return js
        }
        guard let block = native.blocks[id] else {
            throw BridgeInputError("\(path): Config API '\(id)' is not declared in the app's native security file (\(native.source))")
        }
        func fixed(_ key: String) -> BridgeInputError {
            BridgeInputError("\(path).\(key): differs from the app's native security file (\(native.source)); the native value is fixed")
        }
        func relaxation(_ key: String, _ asked: Bool, _ allowed: Bool) throws {
            if asked && !allowed {
                throw BridgeInputError("\(path).\(key): refused; the app's native security file (\(native.source)) does not allow it")
            }
        }
        try relaxation("allowUnsigned", js.allowUnsigned, block.allowUnsigned)
        try relaxation("allowUnpinnedConfigApi", js.allowUnpinned, block.allowUnpinnedConfigApi)
        try relaxation("allowServerGeneratedKey", js.allowServerKey, block.allowServerGeneratedKey)

        var out = js
        if let n = block.bootstrapPins {
            if let j = js.bootstrapPins, !NativeSecurity.samePins(j, n) { throw fixed("bootstrapPins") }
            out.bootstrapPins = n
        }
        if let n = block.signaturePublicKeys {
            if let j = js.oneKey.map({ [$0] }) ?? js.keys {
                if !NativeSecurity.sameKeys(j, n) { throw fixed(js.oneKey != nil ? "signaturePublicKey" : "signaturePublicKeys") }
            } else {
                out.keys = n
            }
        }
        func one<T: Equatable>(_ key: String, _ n: T?, _ j: T?) throws -> T? {
            guard let n else { return j }
            if let j, j != n { throw fixed(key) }
            return n
        }
        func list(_ key: String, _ n: [String]?, _ j: [String]?) throws -> [String]? {
            guard let n else { return j }
            if let j, !NativeSecurity.sameKeys(j, n) { throw fixed(key) }
            return n
        }
        out.requiredSignatures = try one("requiredSignatures", block.requiredSignatures, js.requiredSignatures)
        out.recoveryKeys = try list("recoveryPublicKeys", block.recoveryPublicKeys, js.recoveryKeys)
        out.requiredRecovery = try one("requiredRecoverySignatures", block.requiredRecoverySignatures, js.requiredRecovery)
        out.serverScope = try one("serverScope", block.serverScope, js.serverScope)
        out.clientCaPins = try list("clientCaPins", block.clientCaPins, js.clientCaPins)
        // The file is the source of truth for the relaxations too.
        out.allowUnsigned = block.allowUnsigned
        out.allowUnpinned = block.allowUnpinnedConfigApi
        out.allowServerKey = block.allowServerGeneratedKey
        return out
    }

    static func staticPins(path: String, js: CertificateConfig?, native: NativeSecurity?) throws -> CertificateConfig? {
        guard let native else { return js }
        guard let n = native.staticPins else {
            if js != nil { throw BridgeInputError("\(path): not declared in the app's native security file (\(native.source))") }
            return nil
        }
        if let js, !NativeSecurity.sameStaticPins(js, n) {
            throw BridgeInputError("\(path): differs from the app's native security file (\(native.source)); the native value is fixed")
        }
        return n
    }
}
