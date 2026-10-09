import Foundation
import Security

/// `PinVault-Proof` (`ATTESTATION.md` §5.1): a DPoP proof (RFC 9449) of one
/// request, signed by the device key the `PinVault-Token`'s `cnf.jkt` names
/// (Kotlin `TokenProof`).
///
/// ```
/// header  {"typ":"dpop+jwt","alg":"ES256","jwk":{"kty":"EC","crv":"P-256","x":"…","y":"…"}}
/// payload {"jti":"…","htm":"GET","htu":"https://api.example.com/v1/me","iat":…,"ath":"…"}
/// ```
///
/// Every value is base64url, a number, an upper-case method or an encoded
/// URL, so the JSON is written by hand: nothing in it needs escaping.
enum TokenProof {
    static let header = "PinVault-Proof"

    /// The proof for `method` `url` carrying `token`, signed by `sign` (a DER
    /// `ECDSA-Sig-Value`, as Security makes it) over `publicKey`; `iat` is
    /// `nowSeconds`. Nil for a method that is not plain upper-case letters, a
    /// URL without scheme and host, or a key that is not P-256.
    static func make(
        method: String,
        url: URL,
        token: String,
        publicKey: SecKey,
        nowSeconds: Int64,
        sign: (Data) throws -> Data
    ) throws -> String? {
        guard (1...16).contains(method.utf8.count), method.utf8.allSatisfy({ $0 >= 0x41 && $0 <= 0x5A }) else { return nil }
        guard let htu = htu(url) else { return nil }
        guard let point = SecKeyCopyExternalRepresentation(publicKey, nil) as Data?, point.count == 65, point.first == 0x04 else { return nil }
        let x = Base64.encodeURL(point.subdata(in: 1..<33))
        let y = Base64.encodeURL(point.subdata(in: 33..<65))
        let header = #"{"typ":"dpop+jwt","alg":"ES256","jwk":{"kty":"EC","crv":"P-256","x":"\#(x)","y":"\#(y)"}}"#
        var jtiBytes = Data(count: 16)
        let status = jtiBytes.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 16, $0.baseAddress!) }
        guard status == errSecSuccess else { return nil }
        let jti = Base64.encodeURL(jtiBytes)
        let payload = #"{"jti":"\#(jti)","htm":"\#(method)","htu":"\#(htu)","iat":\#(nowSeconds),"ath":"\#(tokenHash(token))"}"#
        let input = Base64.encodeURL(Data(header.utf8)) + "." + Base64.encodeURL(Data(payload.utf8))
        guard let raw = derToRaw(try sign(Data(input.utf8))) else { return nil }
        return input + "." + Base64.encodeURL(raw)
    }

    /// RFC 9449 `htu`: scheme and host lower-cased, the port when not the
    /// scheme's default, the percent-encoded path (`/` when empty); no query or fragment.
    static func htu(_ url: URL) -> String? {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              let scheme = components.scheme?.lowercased(), scheme == "https" || scheme == "http",
              let rawHost = components.percentEncodedHost?.lowercased(), !rawHost.isEmpty else { return nil }
        let host = rawHost.contains(":") && !rawHost.hasPrefix("[") ? "[\(rawHost)]" : rawHost
        let defaultPort = scheme == "https" ? 443 : 80
        let port = components.port.flatMap { $0 == defaultPort ? nil : ":\($0)" } ?? ""
        let path = components.percentEncodedPath.isEmpty ? "/" : components.percentEncodedPath
        guard path.utf8.allSatisfy({ $0 > 0x20 && $0 < 0x7F && $0 != 0x22 && $0 != 0x5C }) else { return nil }
        return "\(scheme)://\(host)\(port)\(path)"
    }

    /// `ath`: base64url SHA-256 of the token.
    static func tokenHash(_ token: String) -> String {
        Base64.encodeURL(Hashing.sha256(Data(token.trimmingCharacters(in: .whitespacesAndNewlines).utf8)))
    }

    /// A DER `SEQUENCE { INTEGER r, INTEGER s }` as JWS ES256 `r‖s` (32 bytes each); nil when it is not one.
    static func derToRaw(_ der: Data) -> Data? {
        let bytes = [UInt8](der)
        var i = 0
        func byte() -> Int? {
            guard i < bytes.count else { return nil }
            defer { i += 1 }
            return Int(bytes[i])
        }
        func length() -> Int? {
            guard let first = byte() else { return nil }
            if first < 0x80 { return first }
            guard first == 0x81, let next = byte(), next >= 0x80 else { return nil }
            return next
        }
        func integer() -> [UInt8]? {
            guard byte() == 0x02, let len = length(), (1...33).contains(len), i + len <= bytes.count else { return nil }
            var value = Array(bytes[i..<(i + len)])
            i += len
            // Positive: no sign bit set, and not zero.
            guard value[0] & 0x80 == 0, value.contains(where: { $0 != 0 }) else { return nil }
            while value.count > 1 && value[0] == 0 { value.removeFirst() }
            guard value.count <= 32 else { return nil }
            return [UInt8](repeating: 0, count: 32 - value.count) + value
        }
        guard byte() == 0x30, let total = length(), i + total == bytes.count,
              let r = integer(), let s = integer(), i == bytes.count else { return nil }
        return Data(r + s)
    }
}
