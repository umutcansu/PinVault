// The plugin's own `fetch` (the Swift twin of PinnedFetch.kt): parsed strictly,
// sent through the pinned session the library hands out
// (`PinVault.shared.session()` or `session(settings:)`), HTTPS only, bounded.
// PinVault's sessions never follow a redirect from https into plain http.
import Foundation
import PinVault

public struct FetchRequest {
    public let url: URL
    public let method: String
    public let headers: [(String, String)]
    public let body: Data?
    public let responseEncoding: String
    public let timeoutMs: Int64?
    public let maxResponseBytes: Int64
    public let settings: HttpConnectionSettings?
}

public struct ResponseTooLargeError: Error, CustomStringConvertible {
    public let limit: Int64
    public var description: String { "Response larger than \(limit) bytes" }
}

public enum PinnedFetch {
    public static let maxRequestBytes: Int64 = 10 * 1024 * 1024
    public static let defaultMaxResponseBytes: Int64 = 10 * 1024 * 1024
    public static let maxResponseBytesLimit: Int64 = 50 * 1024 * 1024
    static let methods: Set<String> = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
    static let tokenChars = CharacterSet(charactersIn: "!#$%&'*+.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-")

    public static func parse(_ json: String) throws -> FetchRequest {
        let f = try StrictJSON.parseObject(json, path: "request", maxChars: Int(maxRequestBytes * 4 / 3) + 64 * 1024)
        let urlText = try f.requireString("url", maxLength: 8192)
        guard let url = URL(string: urlText), url.host != nil else { throw BridgeInputError("request.url: not a valid URL") }
        guard url.scheme?.lowercased() == "https" else {
            throw BridgeInputError("request.url: only https:// URLs go through the pinned client")
        }
        let method = (try f.string("method", maxLength: 16) ?? "GET").uppercased()
        guard methods.contains(method) else { throw BridgeInputError("request.method: '\(method)' is not supported") }
        var headers: [(String, String)] = []
        for (name, value) in (try f.stringMap("headers", maxItems: 128, maxKeyLength: 256, maxValueLength: 8192) ?? [:]).sorted(by: { $0.key < $1.key }) {
            guard name.unicodeScalars.allSatisfy({ tokenChars.contains($0) }) else {
                throw BridgeInputError("request.headers: '\(name.prefix(40))' is not a header name")
            }
            if value.unicodeScalars.contains(where: { $0 == "\r" || $0 == "\n" || $0.value == 0 }) {
                throw BridgeInputError("request.headers.\(name): line breaks are not allowed")
            }
            headers.append((name, value))
        }
        let bodyText = try f.text("body", maxLength: Int(maxRequestBytes * 4 / 3) + 4)
        let bodyEncoding = try ResultMapper.checkEncoding(try f.string("bodyEncoding", maxLength: 16) ?? ResultMapper.utf8)
        var body: Data?
        if let bodyText {
            if bodyEncoding == ResultMapper.base64 {
                guard let d = Data(base64Encoded: bodyText) else { throw BridgeInputError("request.body: not valid Base64") }
                body = d
            } else {
                body = Data(bodyText.utf8)
            }
        }
        if let body, Int64(body.count) > maxRequestBytes { throw BridgeInputError("request.body: larger than \(maxRequestBytes) bytes") }
        if body != nil && (method == "GET" || method == "HEAD") { throw BridgeInputError("request.body: \(method) has no body") }
        let responseEncoding = try ResultMapper.checkEncoding(try f.string("responseEncoding", maxLength: 16) ?? ResultMapper.utf8)
        let timeoutMs = try f.int64("timeoutMs", min: 1, max: 10 * 60 * 1000)
        let maxResponse = try f.int64("maxResponseBytes", min: 1, max: maxResponseBytesLimit) ?? defaultMaxResponseBytes
        var settings: HttpConnectionSettings?
        if let s = try f.object("settings") {
            let d = HttpConnectionSettings()
            settings = HttpConnectionSettings(
                connectTimeout: try s.int64("connectTimeout", min: 0, max: 600) ?? d.connectTimeout,
                readTimeout: try s.int64("readTimeout", min: 0, max: 600) ?? d.readTimeout,
                writeTimeout: try s.int64("writeTimeout", min: 0, max: 600) ?? d.writeTimeout,
                callTimeout: try s.int64("callTimeout", min: 0, max: 600) ?? d.callTimeout
            )
            try s.finish()
        }
        try f.finish()
        return FetchRequest(
            url: url, method: method, headers: headers, body: body, responseEncoding: responseEncoding,
            timeoutMs: timeoutMs, maxResponseBytes: maxResponse, settings: settings
        )
    }

    public static func urlRequest(_ r: FetchRequest) -> URLRequest {
        var request = URLRequest(url: r.url)
        request.httpMethod = r.method
        for (name, value) in r.headers { request.addValue(value, forHTTPHeaderField: name) }
        request.httpBody = r.body
        if let t = r.timeoutMs { request.timeoutInterval = Double(t) / 1000 }
        return request
    }

    /// Runs `request` on `session` (a pinned session from the library). The
    /// library stops reading once the body passes `maxResponseBytes` (a
    /// declared `Content-Length` over it is refused before the body is read).
    public static func execute(_ session: PinnedSession, _ r: FetchRequest) async throws -> [String: Any] {
        let (data, response) = try await session.data(for: urlRequest(r), maxResponseBytes: r.maxResponseBytes)
        guard let http = response as? HTTPURLResponse else { throw BridgeInputError("not an HTTP response") }
        return try map(http, data, r)
    }

    public static func map(_ http: HTTPURLResponse, _ data: Data, _ r: FetchRequest) throws -> [String: Any] {
        // The transport enforced the bound while reading; this is a second look.
        if Int64(data.count) > r.maxResponseBytes { throw ResponseTooLargeError(limit: r.maxResponseBytes) }
        var headers: [String: String] = [:]
        for (k, v) in http.allHeaderFields {
            guard let name = (k as? String)?.lowercased() else { continue }
            let value = "\(v)"
            headers[name] = headers[name].map { "\($0), \(value)" } ?? value
        }
        return [
            "status": http.statusCode,
            "url": http.url?.absoluteString ?? r.url.absoluteString,
            "headers": headers,
            "body": ResultMapper.encode(data, r.responseEncoding),
            "bodyEncoding": r.responseEncoding,
        ]
    }
}
