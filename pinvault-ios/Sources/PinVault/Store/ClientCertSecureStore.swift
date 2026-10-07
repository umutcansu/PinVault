import Foundation

/// Encrypted storage for the device's mTLS client credentials, one entry per
/// label (`default` for the Config API, `host_<hostname>` for host certs).
///
/// Three forms live side by side under different key prefixes:
/// - `client_p12_<label>`: a PKCS12 bundle (key and certificate together,
///   Base64). Only what is left when the Keychain refused to import a key
///   that arrived in a PKCS12; the library's own paths never keep one otherwise.
/// - `client_imported_<label>`: the PEM certificate chain of a key that came
///   in a PKCS12 and was imported into the Keychain (``ImportedClientKeys``);
///   the P12 bytes are not kept.
/// - `client_chain_<label>`: a PEM certificate chain issued over the device's
///   own identity key, which lives in the Secure Enclave or the Keychain
///   (``ClientIdentityKeyProvider``) and is never stored here.
///
/// Next to them, `client_pending_<label>`: an enrollment request that waits for
/// an administrator's approval.
///
/// A label has one form at a time; ``mode(_:)`` says which. Everything is kept
/// in ``SecurePreferences`` (keys in the Keychain), file
/// `pinvault_secure_client_cert`, namespace `pinvault_client_cert`. Private
/// keys never come here.
final class ClientCertSecureStore: Sendable {

    enum Mode: Sendable, Equatable { case none, p12, chain, imported }

    /// An enrollment request an administrator has not decided on yet; see ``savePendingRequest(_:requestId:clientId:)``.
    struct PendingRequest: Sendable, Equatable {
        let requestId: String
        let clientId: String?
    }

    static let fileName = "pinvault_secure_client_cert"
    /// The namespace inside the file (the name of the 2.0.x Android file).
    static let namespace = "pinvault_client_cert"
    static let defaultLabel = "default"

    private static let p12Prefix = "client_p12_"
    private static let chainPrefix = "client_chain_"
    private static let importedPrefix = "client_imported_"
    private static let pendingPrefix = "client_pending_"
    private static let pendingSeparator = "\n"
    /// PEM never contains this, so joining the chain with it is unambiguous.
    private static let chainSeparator = "\n\n"

    private let prefs: any PreferenceStore
    private let log = PinVaultLog.tag("ClientCertSecureStore")

    /// The store over `prefs` (tests: ``InMemoryPreferences`` or a test ``SecurePreferences``).
    init(prefs: any PreferenceStore) {
        self.prefs = prefs
    }

    /// The app's store. Throws ``PinVaultError/storeUnreadable(message:cause:)``
    /// when the store keys cannot be used right now.
    static func open(environment: SecureStoreEnvironment = .shared) throws -> ClientCertSecureStore {
        ClientCertSecureStore(prefs: try SecurePreferences.open(fileName: fileName, namespace: namespace, environment: environment))
    }

    /// The same store, strict: a Keychain failure on a read throws
    /// ``PinVaultError/storeUnreadable(message:cause:)`` instead of reading
    /// "absent". For the enrollment paths, where a credential that merely
    /// cannot be read now must not look like no credential (a new enrollment
    /// would replace it, and a refused one may delete the key it was issued over).
    static func openStrict(environment: SecureStoreEnvironment = .shared) throws -> ClientCertSecureStore {
        ClientCertSecureStore(prefs: try SecurePreferences.openStrict(fileName: fileName, namespace: namespace, environment: environment))
    }

    // MARK: PKCS12 form

    func save(_ label: String, p12: Data) throws {
        try prefs.edit()
            .putString(Self.p12Key(label), Base64.encode(p12))
            .remove(Self.chainKey(label))
            .remove(Self.importedKey(label))
            .remove(Self.pendingKey(label))
            .apply()
        log.d("Client P12 saved")
    }

    func load(_ label: String) throws -> Data? {
        guard let encoded = try prefs.getString(Self.p12Key(label), nil) else { return nil }
        guard let bytes = Base64.decode(encoded) else {
            log.e("Failed to decode a stored P12")
            return nil
        }
        log.d("Client P12 loaded (\(bytes.count) bytes)")
        return bytes
    }

    func hasP12(_ label: String) throws -> Bool { try prefs.contains(Self.p12Key(label)) }

    // MARK: Certificate-chain form (CSR flow)

    /// Stores the PEM chain (leaf first) for `label`, replacing any other form.
    /// Written with `commit()`: a renewed chain must be on disk before the
    /// identity that presents it is swapped in.
    func saveChain(_ label: String, pemChain: [String]) throws {
        guard !pemChain.isEmpty else { throw PinVaultError.illegalArgument("Certificate chain must not be empty") }
        try prefs.edit()
            .putString(Self.chainKey(label), pemChain.joined(separator: Self.chainSeparator))
            .remove(Self.p12Key(label))
            .remove(Self.importedKey(label))
            .remove(Self.pendingKey(label))
            .commit()
        log.d("Client certificate chain saved (\(pemChain.count) certs)")
    }

    func loadChain(_ label: String) throws -> [String]? {
        try Self.split(prefs.getString(Self.chainKey(label), nil))
    }

    func hasChain(_ label: String) throws -> Bool { try prefs.contains(Self.chainKey(label)) }

    // MARK: Imported form (a PKCS12's key moved into the Keychain)

    /// Stores the PEM chain (leaf first) of a key that was imported into the
    /// Keychain, replacing any other form — the P12 bytes included.
    /// `commit()`: the P12 must be gone from disk once the caller drops it.
    func saveImported(_ label: String, pemChain: [String]) throws {
        guard !pemChain.isEmpty else { throw PinVaultError.illegalArgument("Certificate chain must not be empty") }
        try prefs.edit()
            .putString(Self.importedKey(label), pemChain.joined(separator: Self.chainSeparator))
            .remove(Self.p12Key(label))
            .remove(Self.chainKey(label))
            .remove(Self.pendingKey(label))
            .commit()
        log.d("Imported client certificate chain saved (\(pemChain.count) certs)")
    }

    func loadImported(_ label: String) throws -> [String]? {
        try Self.split(prefs.getString(Self.importedKey(label), nil))
    }

    func hasImported(_ label: String) throws -> Bool { try prefs.contains(Self.importedKey(label)) }

    // MARK: Enrollment waiting for approval

    /// Remembers the request an enrollment was answered with (HTTP 202) while
    /// an administrator decides. The device asks again by this id with a CSR
    /// from the same key; storing a credential for `label` forgets it.
    func savePendingRequest(_ label: String, requestId: String, clientId: String?) throws {
        try prefs.edit()
            .putString(Self.pendingKey(label), requestId + Self.pendingSeparator + (clientId ?? ""))
            .commit()
        log.d("Enrollment waits for approval — request \(requestId)")
    }

    func loadPendingRequest(_ label: String) throws -> PendingRequest? {
        guard let stored = try prefs.getString(Self.pendingKey(label), nil) else { return nil }
        let parts = stored.split(separator: Character(Self.pendingSeparator), maxSplits: 1, omittingEmptySubsequences: false)
        let requestId = String(parts[0])
        guard !requestId.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return nil }
        let clientId = parts.count > 1 ? String(parts[1]) : ""
        return PendingRequest(
            requestId: requestId,
            clientId: clientId.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? nil : clientId
        )
    }

    func clearPendingRequest(_ label: String) throws {
        try prefs.edit().remove(Self.pendingKey(label)).apply()
    }

    // MARK: Either form

    func mode(_ label: String) throws -> Mode {
        if try hasChain(label) { return .chain }
        if try hasImported(label) { return .imported }
        if try hasP12(label) { return .p12 }
        return .none
    }

    func exists(_ label: String) throws -> Bool {
        try hasP12(label) || hasChain(label) || hasImported(label)
    }

    func clear(_ label: String) throws {
        try prefs.edit()
            .remove(Self.p12Key(label))
            .remove(Self.chainKey(label))
            .remove(Self.importedKey(label))
            .remove(Self.pendingKey(label))
            .apply()
        log.d("Client credentials cleared")
    }

    func clearAll() throws {
        try prefs.edit().clear().apply()
        log.d("All client credentials cleared")
    }

    // MARK: Keys

    private static func p12Key(_ label: String) -> String { p12Prefix + label }
    private static func chainKey(_ label: String) -> String { chainPrefix + label }
    private static func importedKey(_ label: String) -> String { importedPrefix + label }
    private static func pendingKey(_ label: String) -> String { pendingPrefix + label }

    /// A joined chain back into its PEMs; nil for nothing (or only blanks).
    private static func split(_ joined: String?) -> [String]? {
        guard let joined else { return nil }
        let pems = joined.components(separatedBy: chainSeparator)
            .filter { !$0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }
        return pems.isEmpty ? nil : pems
    }
}
