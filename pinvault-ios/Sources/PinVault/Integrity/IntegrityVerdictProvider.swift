import Foundation

/// A second opinion on the device's integrity from a service of the app's
/// choosing, forwarded verbatim inside the attestation report
/// (`verdictProvider` in `ATTESTATION.md` §3). The library does not read or
/// verify the token: the server does.
///
/// On iOS the library's own App Attest provider (L5) fills `verdictProvider`
/// with `{"provider":"app-attest",…}` when App Attest is available; register
/// one here to send another service's verdict instead.
public protocol IntegrityVerdictProvider: Sendable {
    /// A verdict bound to `nonce` (this round's attestation nonce). Called once
    /// per attestation with a 10 second budget. Return nil (or throw) when no
    /// verdict is available: the report then carries no `verdictProvider`.
    func verdict(nonce: String) async throws -> IntegrityVerdict?
}

/// What an ``IntegrityVerdictProvider`` hands over.
public struct IntegrityVerdict: Sendable, Equatable, Hashable {
    /// Which service, e.g. `"play-integrity"` or `"app-attest"`.
    public var name: String
    /// The service's token, sent verbatim.
    public var token: String

    public init(name: String, token: String) {
        self.name = name
        self.token = token
    }
}

extension IntegrityVerdict: CustomStringConvertible, CustomDebugStringConvertible {
    /// Never prints the token.
    public var description: String { "IntegrityVerdict(name=\(name), token=***)" }
    public var debugDescription: String { description }
}

/// A SHA-256 digest in hex (`sha256:` prefix, colons and any case allowed),
/// normalised to 64 lowercase hex characters; nil when it is not one.
func normalizeSha256Hex(_ value: String) -> String? {
    var cleaned = value.trimmingCharacters(in: .whitespacesAndNewlines)
    if cleaned.hasPrefix("sha256:") { cleaned.removeFirst("sha256:".count) }
    if cleaned.hasPrefix("SHA256:") { cleaned.removeFirst("SHA256:".count) }
    cleaned = cleaned.replacingOccurrences(of: ":", with: "").lowercased()
    guard cleaned.utf8.count == 64,
          cleaned.utf8.allSatisfy({ ($0 >= 0x30 && $0 <= 0x39) || ($0 >= 0x61 && $0 <= 0x66) }) else { return nil }
    return cleaned
}
