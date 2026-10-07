import Foundation
import Security

/// Asks the Keychain where a key lives (Kotlin `KeyInspector`, which asks the
/// Android Keystore's `KeyInfo`): a key on the Secure Enclave token is
/// ``KeySecurityLevel/secureEnclave``, any other key the Keychain describes is
/// ``KeySecurityLevel/software``. A key it cannot describe is
/// ``KeySecurityLevel/unknown`` — never a guess at hardware.
enum KeyInspector {

    private static let log = PinVaultLog.tag("KeyInspector")

    static func securityLevel(_ key: SecKey) -> KeySecurityLevel {
        guard let attributes = SecKeyCopyAttributes(key) as? [CFString: Any] else {
            log.w("Could not read the Keychain's description of a key")
            return .unknown
        }
        if let token = attributes[kSecAttrTokenID] as? String, token == (kSecAttrTokenIDSecureEnclave as String) {
            return .secureEnclave
        }
        return .software
    }

    /// ``securityLevel(_:)`` of an identity's private key; ``KeySecurityLevel/unknown`` when it has none.
    static func securityLevel(_ identity: SecIdentity) -> KeySecurityLevel {
        var key: SecKey?
        guard SecIdentityCopyPrivateKey(identity, &key) == errSecSuccess, let key else { return .unknown }
        return securityLevel(key)
    }

    /// `EC` / `RSA` (the JCA algorithm name of the key), for logs.
    static func algorithm(_ key: SecKey) -> String {
        let type = (SecKeyCopyAttributes(key) as? [CFString: Any])?[kSecAttrKeyType] as? String
        if type == (kSecAttrKeyTypeECSECPrimeRandom as String) || type == (kSecAttrKeyTypeEC as String) { return "EC" }
        if type == (kSecAttrKeyTypeRSA as String) { return "RSA" }
        return type ?? "unknown"
    }
}
