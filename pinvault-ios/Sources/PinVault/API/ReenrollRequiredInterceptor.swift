import Foundation

/// Spots the server's "this identity is revoked" answer on any request of a
/// Config API — config, scoped config, vault files, device key registration,
/// reports — not only on renewal (Kotlin `ReenrollRequiredInterceptor`).
///
/// An mTLS listener answers a revoked identity `403 {"error":"reenroll_required"}`
/// on every request. Only the renewal endpoint used to read it, so a revoked
/// device kept running on its stored config until its renewal came due.
///
/// The listener also gets the client certificate the connection presented, or
/// nil when it presented none. The answer itself is not signed: what may
/// follow from it depends on whether the server was looking at this device's
/// identity when it gave it (vault files are wiped only then — L3).
///
/// The response goes on untouched.
///
/// iOS limit: on a connection where the server asked for a client
/// certificate, URLSession turns ANY HTTP 403 into
/// `URLError.clientCertificateRequired` and drops the response (neither the
/// completion handler nor the data delegate sees it; 409 / 410 pass through).
/// Such a refusal reaches the caller as ``PinVaultError/sslHandshake(message:cause:)``
/// with that `URLError`, and is not seen here — an mTLS listener has to answer
/// iOS clients with another status for this sniff to work.
struct ReenrollRequiredInterceptor: PinnedInterceptor {

    static let reenrollRequired = "reenroll_required"
    static let maxPeekBytes = 8 * 1024

    let onReenrollRequired: @Sendable (_ reason: String, _ presented: X509Certificate?) -> Void

    init(onReenrollRequired: @escaping @Sendable (_ reason: String, _ presented: X509Certificate?) -> Void) {
        self.onReenrollRequired = onReenrollRequired
    }

    func intercept(
        _ exchange: PinnedExchange,
        proceed: @Sendable (PinnedExchange) async throws -> PinnedResponse
    ) async throws -> PinnedResponse {
        let response = try await proceed(exchange)
        if response.statusCode == 403, let reason = Self.reenrollReason(response.data) {
            onReenrollRequired(reason, response.presentedClientCertificate)
        }
        return response
    }

    /// The server's message when `body` says `reenroll_required`; nil for any
    /// other 403 (the first 8 KiB are read, as OkHttp's `peekBody` would).
    static func reenrollReason(_ body: Data) -> String? {
        guard let json = try? JSONSerialization.jsonObject(with: body.prefix(maxPeekBytes)) as? [String: Any],
              optString(json["error"]) == reenrollRequired else { return nil }
        let message = optString(json["message"])
        return message.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? reenrollRequired : message
    }

    /// `JSONObject.optString`: "" when absent or null, the value's text otherwise.
    private static func optString(_ value: Any?) -> String {
        switch value {
        case nil, is NSNull: return ""
        case let string as String: return string
        case let number as NSNumber: return number.stringValue
        default: return ""
        }
    }
}
