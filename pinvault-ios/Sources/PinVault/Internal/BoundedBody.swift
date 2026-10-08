import Foundation

/// Reads HTTP response bodies with a ceiling (Kotlin `BoundedBody`). A body
/// URLSession buffers whole is whatever the server sends, so a hostile or
/// broken server (or whoever holds the TLS key) could answer a config or vault
/// request with gigabytes and take the app down. Every body the library's
/// Config API client reads goes through a ``Limit``.
///
/// A declared `Content-Length` above the limit is refused before a byte of the
/// body is kept; a body without one (chunked) is counted while it arrives and
/// refused as soon as it passes the limit — the transport then cancels the
/// task, so at most one network chunk past the limit is ever received.
enum BoundedBody {

    /// Config envelopes and other JSON the library parses: 1 MiB.
    static let configMaxBytes: Int64 = 1 << 20

    /// Small answers: key registration, enrollment (a P12 or a PEM chain),
    /// renewal, attestation, error bodies: 256 KiB.
    static let smallMaxBytes: Int64 = 256 << 10

    /// A vault file: 64 MiB. The reference server caps uploads at
    /// `VAULT_MAX_FILE_BYTES` (50 MB by default), so a file the server accepted
    /// fits; the library has no per-file size in its config to be stricter with.
    static let vaultMaxBytes: Int64 = 64 << 20

    /// What is kept of an answer the library only quotes or sniffs (an error
    /// status): enough for `ReenrollRequiredInterceptor`'s 8 KiB peek.
    static let errorPrefixBytes = 8 * 1024

    /// How the transport reads one response's body.
    struct Limit: Sendable {
        /// The most a body read whole may be; longer ones are refused.
        let maxBytes: Int64
        /// Names the body in the refusal ("config", "vault file", …).
        let what: String
        /// What is kept of a body that is not read whole: its first bytes, never refused (`readPrefix`).
        let prefixBytes: Int
        /// Which statuses' bodies are read whole; the others are cut at ``prefixBytes``.
        let readWhole: @Sendable (Int) -> Bool

        init(maxBytes: Int64, what: String, prefixBytes: Int = BoundedBody.errorPrefixBytes,
             readWhole: @escaping @Sendable (Int) -> Bool = { (200..<300).contains($0) }) {
            precondition(maxBytes > 0, "maxBytes must be positive")
            self.maxBytes = maxBytes
            self.what = what
            self.prefixBytes = max(prefixBytes, 0)
            self.readWhole = readWhole
        }

        /// Every status read whole: what Kotlin's unconditional `smallBody` / `readBytes` do.
        static func always(_ maxBytes: Int64, _ what: String) -> Limit {
            Limit(maxBytes: maxBytes, what: what, readWhole: { _ in true })
        }

        /// Nothing read whole: the first `bytes` of any answer (a body the library does not read).
        static func prefix(_ bytes: Int) -> Limit {
            Limit(maxBytes: Int64(max(bytes, 1)), what: "response", prefixBytes: bytes, readWhole: { _ in false })
        }
    }

    /// The first `maxBytes` of `data` as text (UTF-8, malformed bytes
    /// replaced), for error answers that are only quoted (Kotlin `readPrefix`).
    static func prefixText(_ data: Data, _ maxBytes: Int) -> String {
        String(decoding: data.prefix(max(maxBytes, 0)), as: UTF8.self)
    }

    /// A body as text: the charset the response names, UTF-8 when it names none
    /// (Kotlin `readString`).
    static func text(_ data: Data, _ response: URLResponse?) -> String {
        if let name = response?.textEncodingName {
            let cf = CFStringConvertIANACharSetNameToEncoding(name as CFString)
            if cf != kCFStringEncodingInvalidId {
                let encoding = String.Encoding(rawValue: CFStringConvertEncodingToNSStringEncoding(cf))
                if let decoded = String(data: data, encoding: encoding) { return decoded }
            }
        }
        return String(decoding: data, as: UTF8.self)
    }
}

/// Collects one response body under a ``BoundedBody/Limit`` as it arrives.
/// Not thread-safe on its own: the transport feeds it from one delegate queue.
struct BoundedBuffer {

    enum Mode: Equatable {
        /// No ceiling (sessions handed to the app).
        case unbounded
        /// Read whole, refused once longer than the ceiling.
        case whole(Int64)
        /// Cut at this many bytes, never refused.
        case prefix(Int)
    }

    private let limit: BoundedBody.Limit?
    private(set) var mode: Mode = .unbounded
    private(set) var data = Data()
    /// True once a prefix is complete: the rest of the body is not wanted.
    private(set) var isComplete = false

    init(limit: BoundedBody.Limit?) {
        self.limit = limit
    }

    /// The response head arrived. Throws ``ResponseTooLargeException`` when its
    /// declared length (`-1` = unknown) is above the ceiling of a whole read.
    mutating func begin(statusCode: Int, declaredLength: Int64) throws {
        guard let limit else {
            mode = .unbounded
            return
        }
        if limit.readWhole(statusCode) {
            mode = .whole(limit.maxBytes)
            if declaredLength > limit.maxBytes {
                throw ResponseTooLargeException(what: limit.what, maxBytes: limit.maxBytes, declared: declaredLength)
            }
        } else {
            mode = .prefix(limit.prefixBytes)
            if limit.prefixBytes == 0 { isComplete = true }
        }
    }

    /// A piece of the body. Throws ``ResponseTooLargeException`` as soon as a
    /// whole read passes its ceiling (keeping at most one byte over it).
    mutating func append(_ chunk: Data) throws {
        switch mode {
        case .unbounded:
            data.append(chunk)
        case .whole(let maxBytes):
            let room = maxBytes - Int64(data.count) + 1
            data.append(chunk.prefix(Int(clamping: max(room, 0))))
            if Int64(data.count) > maxBytes {
                throw ResponseTooLargeException(what: limit?.what ?? "response", maxBytes: maxBytes, declared: nil)
            }
        case .prefix(let bytes):
            guard !isComplete else { return }
            data.append(chunk.prefix(max(bytes - data.count, 0)))
            if data.count >= bytes { isComplete = true }
        }
    }
}

/// A response body longer than the library reads for that kind of answer
/// (Kotlin `ResponseTooLargeException`, an `IOException`). `declared` is the
/// `Content-Length` when the refusal came from it, nil when the body was cut
/// off while it was being read.
struct ResponseTooLargeException: Error, Sendable, Equatable, CustomStringConvertible, LocalizedError {
    let what: String
    let maxBytes: Int64
    let declared: Int64?

    var message: String {
        "The \(what) response body exceeds \(maxBytes) bytes" + (declared.map { " (Content-Length: \($0))" } ?? "") + "; refused"
    }

    var errorDescription: String? { message }
    var description: String { "ResponseTooLargeException: \(message)" }
}
