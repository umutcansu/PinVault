import Foundation

/// Turns a signed config envelope into a config that may be used, for one
/// Config API block. The same checks apply whoever fetched the envelope — the
/// library's HTTP client or a custom API that adopts ``SignedConfigSource`` —
/// and, minus the freshness window, when a stored envelope is read back.
///
/// The signatures are checked over the exact UTF-8 bytes of the `payload`
/// string as it arrived; the JSON inside is parsed only after that.
///
/// `serverScope`: the block's `serverScope`; when set, the signed payload must
/// carry exactly this `configApiId`. One signing key often serves several
/// Config APIs; without the check an envelope signed for another of them is
/// accepted here.
final class SignedConfigVerifier: Sendable {
    /// The payload field that names the Config API a config was signed for.
    static let scopeField = "configApiId"

    private static let defaultFailure =
        "Config signature verification failed — possible tampering detected. Keeping previous safe config."

    /// Signature entries kept with a stored config; verification looks at no more either.
    private static let maxStoredSignatures = 16

    /// A config whose envelope verified, with the envelope to store next to it.
    struct Verified: Sendable {
        let config: CertificateConfig
        let envelope: StoredEnvelope
    }

    private let trust: SignatureTrust
    private let serverScope: String?
    /// The time a config's expiry is judged by: `clock`, or the later of it
    /// and the block's trusted clock (``expiryNow(config:wall:trustedNow:issuedAtWatermark:)``). Nil = `clock`.
    private let trustedNow: (@Sendable () throws -> Int64)?
    /// The highest `issuedAt` this block has accepted (0 = none).
    private let issuedAtWatermark: @Sendable () throws -> Int64
    /// Wall clock, Unix ms: ``LibraryClock`` by default, so the E2E clock
    /// offset reaches expiry as `date -s` does on Android.
    private let clock: @Sendable () -> Int64
    private let log = PinVaultLog.tag("SignedConfigVerifier")

    init(
        trust: SignatureTrust,
        serverScope: String? = nil,
        trustedNow: (@Sendable () throws -> Int64)? = nil,
        issuedAtWatermark: @escaping @Sendable () throws -> Int64 = { 0 },
        clock: @escaping @Sendable () -> Int64 = LibraryClock.wallMillis
    ) {
        self.trust = trust
        self.serverScope = serverScope
        self.trustedNow = trustedNow
        self.issuedAtWatermark = issuedAtWatermark
        self.clock = clock
    }

    /// Version of the signing-key set in force (0 = the compiled-in keys).
    func keySetVersion() throws -> Int { try trust.keySetVersion() }

    /// See ``SignatureTrust/anchorsFingerprint()``.
    func anchorsFingerprint() -> String { trust.anchorsFingerprint() }

    func keySetBelowFloor() throws -> Bool { try trust.keySetBelowFloor() }

    /// Applies a signing-key set riding along with `signed`, if it is newer.
    /// FIRST, before ``verifyFetched(_:failureMessage:)``: the config in the
    /// same response may already be signed by a key that set introduces. A set
    /// that fails its own checks throws and fails the whole response; a valid
    /// one stays applied even if the config then fails, so a revocation sticks.
    ///
    /// - Returns: true when a newer set was applied.
    @discardableResult
    func applyKeySet(_ signed: SignedConfigResponse) throws -> Bool {
        try trust.applyKeySetUpdate(signed.signingKeys)
    }

    /// Checks a freshly fetched envelope: signatures, the scope it was signed
    /// for, and its freshness — `issuedAt` and `expiresAt` must both be there
    /// and `expiresAt` must not have passed. Throws
    /// ``PinVaultError/security(message:cause:)`` otherwise (and
    /// `storeUnreadable` when the key set cannot be read); `failureMessage`
    /// words a signature failure.
    func verifyFetched(
        _ signed: SignedConfigResponse,
        failureMessage: (_ detail: String) -> String = { SignedConfigVerifier.defaultFailure + $0 }
    ) throws -> Verified {
        guard let envelope = Self.envelopeOf(signed) else {
            throw PinVaultError.security(message: failureMessage(" The envelope has no payload."))
        }
        let verification = try trust.verifyConfig(payload: envelope.payload, entries: envelope.signatures)
        if !verification.ok { throw PinVaultError.security(message: failureMessage(verification.detail)) }
        log.d("Config signature verified ✓ — signed by [\(verification.signedBy.joined(separator: ", "))]")

        try checkScope(envelope.payload)
        let config = try Self.parse(envelope.payload)
        try enforceFreshness(config)
        return Verified(config: config, envelope: envelope)
    }

    /// The config inside a stored `envelope` when its signatures still verify
    /// against the keys trusted NOW (a revoked key no longer counts), it was
    /// signed for this block's scope and its content is well-formed; nil
    /// otherwise. Expiry is left to the caller: an expired stored config has
    /// its own handling (grace, refetch).
    ///
    /// Throws ``PinVaultError/storeUnreadable(message:cause:)`` when the
    /// signing-key set cannot be read right now — that is "cannot tell", not
    /// "does not verify".
    func verifyStored(_ envelope: StoredEnvelope) throws -> CertificateConfig? {
        do {
            guard try trust.verifyStoredConfig(payload: envelope.payload, entries: envelope.signatures).ok else { return nil }
            try checkScope(envelope.payload)
            let config = try Self.parse(envelope.payload)
            try PinConfigValidator.validate(config)
            return config
        } catch let error as PinVaultError {
            if case .storeUnreadable = error { throw error }
            log.w("Stored config envelope rejected: \(error.message)")
            return nil
        } catch {
            log.w("Stored config envelope rejected: \(error)")
            return nil
        }
    }

    /// `signatures` (several signers) wins over the single legacy field. The
    /// wire model reads an absent `payload` as "", which counts as none.
    static func envelopeOf(_ signed: SignedConfigResponse) -> StoredEnvelope? {
        if signed.payload.isEmpty { return nil }
        let single = SignatureEntry(keyId: signed.keyId, signature: signed.signature)
        let entries = signed.signatures.flatMap { $0.isEmpty ? nil : $0 } ?? [single]
        // Only what can be stored and read back: entries that carry a signature.
        let usable = entries.filter { !$0.signature.isBlank }.prefix(maxStoredSignatures)
        return StoredEnvelope(payload: signed.payload, signatures: Array(usable))
    }

    /// The config in a signed payload. `null` or an empty document is "empty";
    /// anything that is not a config throws ``PinVaultError/illegalArgument(_:)``
    /// (Kotlin: Gson's `JsonSyntaxException`).
    static func parse(_ payload: String) throws -> CertificateConfig {
        let trimmed = payload.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty || trimmed == "null" {
            throw PinVaultError.security(message: "Signed config payload is empty.")
        }
        do {
            return try JSONDecoder().decode(CertificateConfig.self, from: Data(payload.utf8))
        } catch let error as PinVaultError {
            throw error
        } catch let error as DecodingError {
            throw PinVaultError.illegalArgument("Signed config payload is not a valid config: \(describe(error))")
        } catch {
            throw PinVaultError.illegalArgument("Signed config payload is not a valid config: \(error)")
        }
    }

    private static func describe(_ error: DecodingError) -> String {
        let context: DecodingError.Context
        switch error {
        case .typeMismatch(_, let c), .valueNotFound(_, let c), .keyNotFound(_, let c), .dataCorrupted(let c): context = c
        @unknown default: return "\(error)"
        }
        let path = context.codingPath.map { $0.intValue.map { "[\($0)]" } ?? ".\($0.stringValue)" }.joined()
        return "\(context.debugDescription) at $\(path)"
    }

    /// The audience check behind `serverScope`. The field is inside the signed
    /// payload, so it cannot be swapped.
    private func checkScope(_ payload: String) throws {
        guard let expected = serverScope else { return }
        let object = (try? JSONSerialization.jsonObject(with: Data(payload.utf8), options: [.fragmentsAllowed])) as? [String: Any]
        guard let actual = Self.scalarString(object?[Self.scopeField]) else {
            throw PinVaultError.security(message:
                "Signed config rejected: its payload names no '\(Self.scopeField)', and this block accepts only configs " +
                    "signed for Config API '\(expected)' (serverScope). The server must write the field into every " +
                    "signed config."
            )
        }
        if actual != expected {
            throw PinVaultError.security(message:
                "Signed config rejected: it was signed for Config API '\(actual.kotlinTake(64))', this block accepts " +
                    "only '\(expected)' (serverScope)."
            )
        }
    }

    /// Gson `asString` on a JSON value: a string, the text of a number or
    /// boolean, or of the one element of an array; nil otherwise (and for null).
    private static func scalarString(_ value: Any?) -> String? {
        switch value {
        case let array as [Any]: return array.count == 1 ? scalarString(array[0]) : nil
        default: return JSONText.gsonString(value)
        }
    }

    /// Rejects signed configs that fall outside the server-controlled
    /// freshness window. Guards against replay of older signed payloads even
    /// when the signature is still cryptographically valid.
    ///
    /// A missing `expiresAt` or `issuedAt` (= 0) is an error rather than
    /// silently accepted — a server that returns signed configs MUST populate
    /// both. Replay against the stored `issuedAt` is caught by the updater.
    private func enforceFreshness(_ config: CertificateConfig) throws {
        let now = try Self.expiryNow(config: config, wall: clock, trustedNow: trustedNow, issuedAtWatermark: issuedAtWatermark)
        if config.expiresAt <= 0 {
            throw PinVaultError.security(message:
                "Signed config missing expiresAt — refusing to apply. " +
                    "Server must populate expiresAt (Unix epoch ms) to enable replay protection."
            )
        }
        if config.issuedAt <= 0 {
            throw PinVaultError.security(message:
                "Signed config missing issuedAt — refusing to apply. " +
                    "Server must populate issuedAt (Unix epoch ms) to enable replay protection."
            )
        }
        if config.expiresAt <= now {
            throw PinVaultError.security(message:
                "Signed config expired: expiresAt=\(config.expiresAt), now=\(now) " +
                    "(stale by \(now &- config.expiresAt)ms). Possible replay attack."
            )
        }
    }

    /// The time against which "already expired" is judged for a fetched
    /// `config`. Normally the trusted clock (the later of the wall clock and
    /// the highest time seen), so setting the device clock back does not let
    /// an expired config in again. Not for a config newer than every config
    /// accepted before: that is the one config that may move a trusted clock
    /// that ran ahead back again (`TrustedClock.resetTo`). Its `issuedAt` is
    /// checked against the watermark anyway.
    static func expiryNow(
        config: CertificateConfig,
        wall: () -> Int64,
        trustedNow: (() throws -> Int64)?,
        issuedAtWatermark: () throws -> Int64
    ) throws -> Int64 {
        let wallNow = wall()
        guard let trustedNow else { return wallNow }
        if config.issuedAt > (try issuedAtWatermark()) { return wallNow }
        return max(wallNow, try trustedNow())
    }
}
