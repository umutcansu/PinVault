import Foundation

/// The value an integrity token is bound to for one enrollment request (see
/// ``IntegrityTokenProvider``):
///
/// ```
/// base64url(SHA-256("pinvault-integrity:v1:" + deviceId + ":" + base64url(SHA-256(csrDer))))
/// ```
///
/// Unpadded Base64url, 43 characters. The server recomputes it from the
/// request it receives; an App Attest token binds `SHA256(UTF8(hash))`
/// (PORTING.md §6). Test vectors shared with the server
/// (SERVER_IMPLEMENTATION_GUIDE.md).
enum IntegrityRequestHash {

    private static let prefix = "pinvault-integrity:v1:"

    static func of(deviceId: String?, csrDer: Data) -> String {
        let csrHash = base64Url(Hashing.sha256(csrDer))
        return base64Url(Hashing.sha256("\(prefix)\(deviceId ?? ""):\(csrHash)"))
    }

    /// RFC 4648 §5 without padding.
    static func base64Url(_ bytes: Data) -> String {
        Base64.encodeURL(bytes)
    }
}
