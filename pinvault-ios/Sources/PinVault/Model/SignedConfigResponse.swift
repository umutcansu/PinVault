import Foundation

/// The signed config envelope the Config API returns. Only `payload` and
/// `signature` are required; the rest is optional and ignored by older clients.
///
/// - `payload`: the config JSON exactly as signed; the signature is over its UTF-8 bytes.
/// - `signature`: Base64 DER ECDSA-SHA256 over `payload` (one of them when several keys sign).
/// - `keyId`: unsigned hint naming the key of `signature` (Base64 SHA-256 of its SPKI).
/// - `signatures`: every signature when the backend signs with several keys (m-of-n); wins over `signature`.
/// - `signingKeys`: a signing-key set authorised by the block's recovery keys.
///
/// Decoding is lenient like Gson: an absent `payload`/`signature` decodes as
/// `""` and `null` entries of `signatures` are dropped, so the verifier
/// refuses such an envelope rather than the decoder.
public struct SignedConfigResponse: Sendable, Equatable, Hashable, Codable {
    public var payload: String
    public var signature: String
    public var keyId: String?
    public var signatures: [SignatureEntry]?
    public var signingKeys: SignedKeySet?

    public init(
        payload: String,
        signature: String,
        keyId: String? = nil,
        signatures: [SignatureEntry]? = nil,
        signingKeys: SignedKeySet? = nil
    ) {
        self.payload = payload
        self.signature = signature
        self.keyId = keyId
        self.signatures = signatures
        self.signingKeys = signingKeys
    }

    enum CodingKeys: String, CodingKey {
        case payload, signature, keyId, signatures, signingKeys
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        payload = try container.decodeIfPresent(String.self, forKey: .payload) ?? ""
        signature = try container.decodeIfPresent(String.self, forKey: .signature) ?? ""
        keyId = try container.decodeIfPresent(String.self, forKey: .keyId)
        signatures = try container.decodeIfPresent([SignatureEntry?].self, forKey: .signatures)?.compactMap { $0 }
        signingKeys = try container.decodeIfPresent(SignedKeySet.self, forKey: .signingKeys)
    }
}

/// One signature over a signed document.
///
/// - `keyId`: optional unsigned hint, Base64 SHA-256 of the signing key's SPKI.
/// - `signature`: Base64 DER ECDSA-SHA256.
public struct SignatureEntry: Sendable, Equatable, Hashable, Codable {
    public var keyId: String?
    public var signature: String

    public init(keyId: String? = nil, signature: String) {
        self.keyId = keyId
        self.signature = signature
    }

    enum CodingKeys: String, CodingKey { case keyId, signature }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        keyId = try container.decodeIfPresent(String.self, forKey: .keyId)
        signature = try container.decodeIfPresent(String.self, forKey: .signature) ?? ""
    }
}

/// A signing-key set: the config-signing keys a device should trust, signed
/// by offline recovery keys. `payload` is JSON, verified byte for byte:
///
/// ```json
/// {"type":"pinvault-signing-keys","version":2,"keys":["MFkw…","MFkw…"],"requiredSignatures":1}
/// ```
///
/// A device applies a set only when its `version` is higher than the one it
/// holds; from then on the set replaces the compiled-in keys.
public struct SignedKeySet: Sendable, Equatable, Hashable, Codable {
    public var payload: String
    public var signatures: [SignatureEntry]

    public init(payload: String, signatures: [SignatureEntry]) {
        self.payload = payload
        self.signatures = signatures
    }

    enum CodingKeys: String, CodingKey { case payload, signatures }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        payload = try container.decodeIfPresent(String.self, forKey: .payload) ?? ""
        signatures = try container.decodeIfPresent([SignatureEntry?].self, forKey: .signatures)?.compactMap { $0 } ?? []
    }
}

/// Wire shape of a signing-key set's payload (see ``SignedKeySet``).
/// Optional throughout, as Gson reads it.
struct SigningKeySetPayload: Sendable, Equatable, Codable {
    var type: String?
    var version: Int
    var keys: [String?]?
    var requiredSignatures: Int?
    /// The Config API (`serverScope`) the set is for; when present and the
    /// block sets `serverScope`, they must match. Older sets omit it.
    var configApiId: String?

    init(type: String? = nil, version: Int = 0, keys: [String?]? = nil, requiredSignatures: Int? = nil, configApiId: String? = nil) {
        self.type = type
        self.version = version
        self.keys = keys
        self.requiredSignatures = requiredSignatures
        self.configApiId = configApiId
    }

    enum CodingKeys: String, CodingKey { case type, version, keys, requiredSignatures, configApiId }

    init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        type = try container.decodeIfPresent(String.self, forKey: .type)
        version = try container.decodeIfPresent(Int.self, forKey: .version) ?? 0
        keys = try container.decodeIfPresent([String?].self, forKey: .keys)
        requiredSignatures = try container.decodeIfPresent(Int.self, forKey: .requiredSignatures)
        configApiId = try container.decodeIfPresent(String.self, forKey: .configApiId)
    }
}
