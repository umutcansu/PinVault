import Foundation

/// `forbidden-as-409` (PORTING.md §4): on a connection where the server asked
/// for a client certificate, URLSession turns any HTTP 403 into
/// `URLError.clientCertificateRequired` (-1206) and drops the body — an iPhone
/// would never see `403 {"error":"reenroll_required"}`, a revoked identity or
/// why a vault file was refused. The library asks the server for a `409` with
/// the same body and `X-PinVault-Status: 403` instead
/// (`X-PinVault-Features: forbidden-as-409`), and the transport hands such an
/// answer to the interceptors and the API client as the 403 it is.
///
/// Who asks: every request of the Config API client (``Policy/always``), and
/// an app request through `session()` / `session(settings:)` / `applyTo` only
/// when the library presents a client identity to its logical host
/// (``Policy/identityHosts``) — other servers never hear of the feature.
enum ForbiddenAsConflict {

    static let featuresHeader = "X-PinVault-Features"
    static let feature = "forbidden-as-409"
    /// Carries the status a remapped response really has.
    static let originalStatusHeader = "X-PinVault-Status"

    enum Policy: Sendable {
        /// Every request (the Config API client).
        case always
        /// Requests to hosts the library presents a client identity to.
        case identityHosts
    }

    /// `features` with the token appended (once).
    static func adding(to features: String?) -> String {
        guard let features, !features.trimmingCharacters(in: .whitespaces).isEmpty else { return feature }
        return requested(features) ? features : "\(features),\(feature)"
    }

    /// True when the `X-PinVault-Features` value names the token.
    static func requested(_ features: String?) -> Bool {
        guard let features else { return false }
        return features.split(separator: ",").contains {
            $0.trimmingCharacters(in: .whitespaces).caseInsensitiveCompare(feature) == .orderedSame
        }
    }

    /// The 403 a `409` + `X-PinVault-Status: 403` stands for; nil for any other response.
    static func normalized(_ response: HTTPURLResponse, url: URL) -> HTTPURLResponse? {
        guard response.statusCode == 409,
              response.value(forHTTPHeaderField: originalStatusHeader)?.trimmingCharacters(in: .whitespaces) == "403"
        else { return nil }
        return HTTPURLResponse(url: url, statusCode: 403, httpVersion: nil, headerFields: headerFields(response))
    }

    /// The header fields of `response` as strings.
    static func headerFields(_ response: HTTPURLResponse) -> [String: String] {
        var fields: [String: String] = [:]
        for (name, value) in response.allHeaderFields {
            if let name = name as? String { fields[name] = "\(value)" }
        }
        return fields
    }
}
