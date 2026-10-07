import Foundation
import Security

/// The device's mTLS identity: a permanent EC P-256 signing key (Secure
/// Enclave when available, else a Keychain software key reporting
/// ``KeySecurityLevel/software``). The client certificate is a short-lived
/// credential issued over it and renewed by signing a CSR with it; the key
/// never leaves the device. One key per client-cert label, Keychain
/// application tag ``ClientIdentityKeys/aliasFor(_:)``.
///
/// Implementations: ``ClientIdentityKeys/secureEnclave(label:)`` (the
/// device's, with the Keychain software fallback) and
/// ``ClientIdentityKeys/software(label:)`` (in memory, for tests).
public protocol ClientIdentityKeyProvider: Sendable {

    /// Generate the key pair if missing. Idempotent.
    func ensureKeyPair() throws

    /// ``ensureKeyPair()`` with an attestation challenge. iOS keys carry no
    /// key attestation, so the challenge is ignored by default.
    func ensureKeyPair(attestationChallenge: Data?) throws

    /// The key's attestation chain (DER, leaf first); always empty on iOS.
    func attestationChain() -> [Data]

    /// True when the key exists (without generating it). The library's
    /// Keychain keys answer true when the Keychain cannot say right now: a
    /// key that is merely unreadable must not read as gone (a stored
    /// certificate over it would be dropped); its use fails instead.
    func exists() -> Bool

    func publicKey() throws -> SecKey

    /// Opaque for Secure Enclave keys: usable only through ``sign(_:)`` and TLS identities.
    func privateKey() throws -> SecKey

    /// ECDSA-SHA256 over `data`, DER `ECDSA-Sig-Value`.
    func sign(_ data: Data) throws -> Data

    /// Base64 SHA-256 of the SubjectPublicKeyInfo — what the server keeps in its registry.
    func spkiSha256() throws -> String

    /// Where the key lives (``KeySecurityLevel/secureEnclave`` or ``KeySecurityLevel/software``);
    /// ``KeySecurityLevel/unknown`` when it cannot be told.
    func securityLevel() -> KeySecurityLevel

    /// Delete the key; the next ``ensureKeyPair()`` makes a new identity.
    func clear() throws
}

extension ClientIdentityKeyProvider {
    public func ensureKeyPair(attestationChallenge: Data?) throws { try ensureKeyPair() }
    public func attestationChain() -> [Data] { [] }
    public func securityLevel() -> KeySecurityLevel { .unknown }

    public func spkiSha256() throws -> String {
        SPKI.pin(try SPKI.der(for: publicKey()))
    }
}

/// Names and constants of the client identity keys (the Kotlin
/// `ClientIdentityKeyProvider.Companion`).
public enum ClientIdentityKeys {
    private static let aliasPrefix = "pinvault_client_identity_ec_"

    /// Keychain application tag of the identity behind the client cert stored under `label`.
    public static func aliasFor(_ label: String) -> String {
        aliasPrefix + label
    }

    /// OID of the Android key attestation extension (unused on iOS; kept for parity).
    public static let attestationExtensionOID = "1.3.6.1.4.1.11129.2.1.17"

    /// SHA-256 of `pinvault-identity-key:v1:<deviceUid>` (UTF-8): the challenge
    /// an identity key is generated with on Android.
    public static func attestationChallenge(deviceUid: String) -> Data {
        Hashing.sha256("pinvault-identity-key:v1:\(deviceUid)")
    }
}

// MARK: - Factories

extension ClientIdentityKeys {

    /// The device's identity key for `label`: a Secure Enclave P-256 key
    /// (`kSecAttrTokenIDSecureEnclave`, `.privateKeyUsage`, this device only),
    /// or — where the Secure Enclave cannot make one — a Keychain software
    /// P-256 key that reports ``KeySecurityLevel/software`` (and is refused
    /// under `requireHardwareBackedKeys()`). Application tag ``aliasFor(_:)``.
    public static func secureEnclave(label: String) -> any ClientIdentityKeyProvider {
        KeychainClientIdentityKeyProvider(alias: aliasFor(label), secureEnclave: true)
    }

    /// A software key held in memory for the process lifetime (Kotlin
    /// `ClientIdentityKeyProvider.software`): for tests and tools without a
    /// Keychain. Separate instances for the same label see the same key, as
    /// they would in the Keychain. Its client certificate cannot be presented
    /// in a TLS handshake (the Keychain pairs certificate and key).
    public static func software(label: String) -> any ClientIdentityKeyProvider {
        InMemoryClientIdentityKeyProvider(alias: aliasFor(label))
    }

    /// A Keychain software key only, never the Secure Enclave: the fallback of
    /// ``secureEnclave(label:)`` on its own (tests of that path).
    static func keychainSoftware(label: String) -> any ClientIdentityKeyProvider {
        KeychainClientIdentityKeyProvider(alias: aliasFor(label), secureEnclave: false)
    }
}

// MARK: - Keychain / Secure Enclave

/// The identity key in the Secure Enclave (preferred) or the Keychain.
final class KeychainClientIdentityKeyProvider: ClientIdentityKeyProvider, Sendable {

    let alias: String
    private let preferSecureEnclave: Bool
    private let options: KeystoreOptions
    private static let log = PinVaultLog.tag("ClientIdentityKeyProvider")
    /// One generation at a time: two keys under one tag would both be found.
    private static let generation = NSLock()

    init(alias: String, secureEnclave: Bool, options: KeystoreOptions = .shared) {
        self.alias = alias
        self.preferSecureEnclave = secureEnclave
        self.options = options
    }

    func ensureKeyPair() throws {
        try ensureKeyPair(attestationChallenge: nil)
    }

    /// Tries, in order: the Secure Enclave, a Keychain software key. iOS keys
    /// carry no key attestation: the challenge is not used.
    func ensureKeyPair(attestationChallenge: Data?) throws {
        Self.generation.lock()
        defer { Self.generation.unlock() }
        if KeychainIdentities.hasPrivateKey(alias: alias) != false {
            Self.log.d("Client identity key exists")
            return
        }
        let attempts = preferSecureEnclave ? [true, false] : [false]
        try options.generating("Client identity key", cleanUp: { try? clear() }) { unlockedDeviceRequired in
            var last: (any Error)?
            for secureEnclave in attempts {
                do {
                    try generate(secureEnclave: secureEnclave, unlockedDeviceRequired: unlockedDeviceRequired)
                    Self.log.i("Client identity key generated (secureEnclave=\(secureEnclave))")
                    // Where it ended up is the Keychain's word, not the request's:
                    // refused and deleted when hardware is required and it is not.
                    try options.checkLevel("Client identity key", securityLevel(), cleanUp: { try clear() })
                    return
                } catch {
                    last = error
                    Self.log.w("Client identity key generation failed (secureEnclave=\(secureEnclave)), trying the next way", error)
                    try? clear()
                }
            }
            throw last ?? PinVaultError.illegalState("client identity key generation failed")
        }
    }

    private func generate(secureEnclave: Bool, unlockedDeviceRequired: Bool) throws {
        let accessible = KeychainIdentities.accessibility(unlockedDeviceRequired: unlockedDeviceRequired)
        var privateAttributes: [CFString: Any] = [
            kSecAttrIsPermanent: true,
            kSecAttrApplicationTag: KeychainIdentities.tag(alias),
            kSecAttrLabel: alias,
        ]
        var attributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits: 256,
            kSecUseDataProtectionKeychain: true,
        ]
        if secureEnclave {
            var error: Unmanaged<CFError>?
            guard let access = SecAccessControlCreateWithFlags(nil, accessible, .privateKeyUsage, &error) else {
                throw PinVaultError.crypto(message: "Secure Enclave access control cannot be made", cause: error?.takeRetainedValue())
            }
            attributes[kSecAttrTokenID] = kSecAttrTokenIDSecureEnclave
            privateAttributes[kSecAttrAccessControl] = access
        } else {
            privateAttributes[kSecAttrAccessible] = accessible
            privateAttributes[kSecAttrIsExtractable] = false
        }
        attributes[kSecPrivateKeyAttrs] = privateAttributes
        var error: Unmanaged<CFError>?
        guard SecKeyCreateRandomKey(attributes as CFDictionary, &error) != nil else {
            throw PinVaultError.crypto(
                message: "\(secureEnclave ? "Secure Enclave" : "Keychain") key generation failed",
                cause: error?.takeRetainedValue()
            )
        }
    }

    func exists() -> Bool {
        // Cannot tell → exists: see the protocol.
        KeychainIdentities.hasPrivateKey(alias: alias) ?? true
    }

    func publicKey() throws -> SecKey {
        guard let publicKey = SecKeyCopyPublicKey(try privateKey()) else {
            throw PinVaultError.crypto(message: "The client identity key has no public half")
        }
        return publicKey
    }

    func privateKey() throws -> SecKey {
        guard let key = try KeychainIdentities.privateKey(alias: alias) else {
            throw PinVaultError.illegalState("Client identity key not found — call ensureKeyPair() first")
        }
        return key
    }

    func sign(_ data: Data) throws -> Data {
        try ClientIdentityKeySigning.sign(data, with: privateKey())
    }

    func securityLevel() -> KeySecurityLevel {
        guard KeychainIdentities.hasPrivateKey(alias: alias) == true, let key = try? privateKey() else { return .unknown }
        return KeyInspector.securityLevel(key)
    }

    /// Deletes the key and the certificates stored for it in the Keychain.
    func clear() throws {
        try KeychainIdentities.deleteKeys(alias: alias)
        KeychainIdentities.removeCertificates(alias: alias)
    }
}

// MARK: - In memory (tests)

/// A software key per alias for the process lifetime (Kotlin
/// `SoftwareClientIdentityKeyProvider`).
final class InMemoryClientIdentityKeyProvider: ClientIdentityKeyProvider, Sendable {

    let alias: String
    private static let log = PinVaultLog.tag("ClientIdentityKeyProvider")

    private final class Entry: @unchecked Sendable {
        let key: SecKey
        let challenge: Data?
        init(key: SecKey, challenge: Data?) {
            self.key = key
            self.challenge = challenge
        }
    }

    private static let keys = Locked<[String: Entry]>([:])
    private static let attestationHook = Locked<(@Sendable (Data) -> [Data])?>(nil)

    /// Tests: stands in for a device attestation key. Given the challenge a key
    /// was generated with, returns its "chain" (any bytes); nil = this "device"
    /// cannot attest.
    static var attestation: (@Sendable (Data) -> [Data])? {
        get { attestationHook.get() }
        set { attestationHook.set(newValue) }
    }

    init(alias: String) {
        self.alias = alias
    }

    func ensureKeyPair() throws {
        try ensureKeyPair(attestationChallenge: nil)
    }

    func ensureKeyPair(attestationChallenge: Data?) throws {
        try Self.keys.withLock { keys in
            if keys[alias] != nil { return }
            let attributes: [CFString: Any] = [
                kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
                kSecAttrKeySizeInBits: 256,
                kSecAttrIsPermanent: false,
            ]
            var error: Unmanaged<CFError>?
            guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
                throw PinVaultError.crypto(message: "Software key generation failed", cause: error?.takeRetainedValue())
            }
            keys[alias] = Entry(key: key, challenge: attestationChallenge)
            Self.log.d("Generated software client identity key")
        }
    }

    /// What ``attestation`` makes of the challenge this key was generated with; empty without either.
    func attestationChain() -> [Data] {
        guard let challenge = Self.keys.withLock({ $0[alias]?.challenge }) else { return [] }
        return Self.attestation?(challenge) ?? []
    }

    func exists() -> Bool { Self.keys.withLock { $0[alias] != nil } }

    func publicKey() throws -> SecKey {
        guard let publicKey = SecKeyCopyPublicKey(try privateKey()) else {
            throw PinVaultError.crypto(message: "The client identity key has no public half")
        }
        return publicKey
    }

    func privateKey() throws -> SecKey {
        guard let entry = Self.keys.withLock({ $0[alias] }) else { throw PinVaultError.illegalState("ensureKeyPair() first") }
        return entry.key
    }

    func sign(_ data: Data) throws -> Data {
        try ClientIdentityKeySigning.sign(data, with: privateKey())
    }

    /// A software key, and says so (tests of `requireHardwareBackedKeys` rely on it).
    func securityLevel() -> KeySecurityLevel { exists() ? .software : .unknown }

    func clear() throws {
        Self.keys.withLock { _ = $0.removeValue(forKey: alias) }
    }
}

/// SHA256withECDSA through Security (`.ecdsaSignatureMessageX962SHA256`: DER `ECDSA-Sig-Value`).
enum ClientIdentityKeySigning {
    static func sign(_ data: Data, with key: SecKey) throws -> Data {
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(key, .ecdsaSignatureMessageX962SHA256, data as CFData, &error) as Data? else {
            throw PinVaultError.crypto(message: "The client identity key cannot sign", cause: error?.takeRetainedValue())
        }
        return signature
    }
}
