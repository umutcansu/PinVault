import Foundation
import XCTest
@testable import PinVault

// Test support of the Config API client, the updater and the façade (L2).

/// The TLS test server every Config API test talks to: the `localhost` leaf
/// under the intermediate, pinned by its key plus the backup pin.
func startConfigApiServer(clientAuth: TestServer.ClientAuth = .none) async throws -> TestServer {
    let server = try TestServer(p12: "server", chain: ["intermediate"], clientAuth: clientAuth)
    try await server.start()
    return server
}

/// The bootstrap pins of ``startConfigApiServer(clientAuth:)``.
var configApiServerPins: [HostPin] {
    [HostPin(hostname: "localhost", sha256: [TLSFixture.pin("leaf"), TLSFixture.backupPin])]
}

extension TestServer {
    /// `https://localhost:<port>/`.
    var baseURL: String { url("/").absoluteString }
}

/// A ``DefaultCertificateConfigApi`` for `server` over a test manager (clock inside the fixtures' validity).
func makeConfigApi(
    _ server: TestServer,
    manager: DynamicSSLManager = testManager(),
    signaturePublicKey: String? = nil,
    signatureTrust: SignatureTrust? = nil,
    clientKeyPassword: String? = nil,
    enrollmentUrl: String? = nil,
    onReenrollRequired: (@Sendable (String, X509Certificate?) -> Void)? = nil,
    serverScope: String? = nil,
    allowServerGeneratedKey: Bool = false,
    configBodyLimit: Int64 = BoundedBody.configMaxBytes,
    vaultBodyLimit: Int64 = BoundedBody.vaultMaxBytes
) -> DefaultCertificateConfigApi {
    DefaultCertificateConfigApi(
        configUrl: server.baseURL,
        signaturePublicKey: signaturePublicKey,
        bootstrapPins: configApiServerPins,
        sslManager: manager,
        signatureTrust: signatureTrust,
        clientKeyPassword: clientKeyPassword,
        enrollmentUrl: enrollmentUrl,
        onReenrollRequired: onReenrollRequired,
        serverScope: serverScope,
        allowServerGeneratedKey: allowServerGeneratedKey,
        configBodyLimit: configBodyLimit,
        vaultBodyLimit: vaultBodyLimit
    )
}

extension TestServer.RecordedRequest {
    /// The comma-separated `X-PinVault-Features` tokens, trimmed.
    var features: [String] {
        (header("X-PinVault-Features") ?? "").split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
    }

    /// The body as a JSON object.
    var jsonBody: [String: Any] {
        (try? JSONSerialization.jsonObject(with: body)) as? [String: Any] ?? [:]
    }

    /// The decoded value of query parameter `name`.
    func query(_ name: String) -> String? {
        URLComponents(string: "https://x" + path)?.queryItems?.first { $0.name == name }?.value
    }
}

/// JSON of a value the way the Kotlin tests' Gson writes it.
func json<T: Encodable>(_ value: T) -> String {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.withoutEscapingSlashes]
    return String(decoding: try! encoder.encode(value), as: UTF8.self)
}

/// A signed config payload with the fields in the Kotlin tests' order.
func signedPayload(
    version: Int,
    issuedAt: Int64,
    expiresAt: Int64,
    pins: [String],
    hosts: [(String, Int)],
    forceUpdate: Bool = false,
    scope: String? = nil
) -> String {
    var fields: [(String, String)] = [
        ("version", String(version)),
        ("pins", JSONText.array(hosts.map { host, hostVersion in
            JSONText.object([
                ("hostname", JSONText.string(host)),
                ("sha256", JSONText.array(pins.map(JSONText.string))),
                ("version", String(hostVersion)),
            ])
        })),
        ("forceUpdate", forceUpdate ? "true" : "false"),
        ("issuedAt", String(issuedAt)),
        ("expiresAt", String(expiresAt)),
    ]
    if let scope { fields.append((SignedConfigVerifier.scopeField, JSONText.string(scope))) }
    return JSONText.object(fields)
}

/// A scriptable ``CertificateConfigApi`` (the Kotlin tests' mockk).
final class FakeConfigApi: CertificateConfigApi, @unchecked Sendable {
    private let lock = NSLock()
    private var _fetch: @Sendable (Int) throws -> CertificateConfig = { _ in throw PinVaultError.io(message: "no config scripted") }
    private var _healthy: @Sendable () throws -> Bool = { true }
    private var _hostCert: @Sendable (String) throws -> Data = { _ in Data() }
    private var _fetches = 0
    private var _scopedFetches = 0
    private var _healthChecks = 0
    private var _hostCertDownloads: [String] = []

    var fetch: @Sendable (Int) throws -> CertificateConfig {
        get { lock.withLock { _fetch } }
        set { lock.withLock { _fetch = newValue } }
    }
    var healthy: @Sendable () throws -> Bool {
        get { lock.withLock { _healthy } }
        set { lock.withLock { _healthy = newValue } }
    }
    var hostCert: @Sendable (String) throws -> Data {
        get { lock.withLock { _hostCert } }
        set { lock.withLock { _hostCert = newValue } }
    }
    var fetches: Int { lock.withLock { _fetches } }
    var scopedFetches: Int { lock.withLock { _scopedFetches } }
    var healthChecks: Int { lock.withLock { _healthChecks } }
    var hostCertDownloads: [String] { lock.withLock { _hostCertDownloads } }

    /// Serves `config` from now on.
    func returns(_ config: CertificateConfig) { fetch = { _ in config } }
    /// Fails every fetch from now on.
    func fails(_ message: String = "offline") { fetch = { _ in throw PinVaultError.io(message: message) } }

    func healthCheck() async throws -> Bool {
        let check = lock.withLock { () -> @Sendable () throws -> Bool in
            _healthChecks += 1
            return _healthy
        }
        return try check()
    }

    func fetchConfig(currentVersion: Int) async throws -> CertificateConfig {
        let body = lock.withLock { () -> @Sendable (Int) throws -> CertificateConfig in
            _fetches += 1
            return _fetch
        }
        return try body(currentVersion)
    }

    func fetchScopedConfig(currentVersion: Int, hosts: [String]?, deviceId: String?) async throws -> CertificateConfig {
        lock.withLock { _scopedFetches += 1 }
        return try await fetchConfig(currentVersion: currentVersion)
    }

    func downloadHostClientCert(hostname: String) async throws -> Data {
        let body = lock.withLock { () -> @Sendable (String) throws -> Data in
            _hostCertDownloads.append(hostname)
            return _hostCert
        }
        return try body(hostname)
    }

    func downloadVaultFile(endpoint: String) async throws -> Data { Data() }

    func enroll(token: String?, deviceId: String?, deviceAlias: String?, deviceUid: String?) async throws -> EnrollmentResult {
        EnrollmentResult(p12Bytes: Data())
    }
}

/// A custom backend that serves signed envelopes — and whose `fetchConfig`
/// must never be asked (the Kotlin `SignedApi`).
final class SignedFakeApi: CertificateConfigApi, SignedConfigSource, @unchecked Sendable {
    private let lock = NSLock()
    private var _next: SignedConfigResponse?
    private var _failure: (any Error)?
    private var _healthy = true
    private var _fetches = 0
    private var _gate: AsyncGate?
    private var _duringHealthCheck: (@Sendable () async -> Void)?

    var next: SignedConfigResponse? {
        get { lock.withLock { _next } }
        set { lock.withLock { _next = newValue } }
    }
    var failure: (any Error)? {
        get { lock.withLock { _failure } }
        set { lock.withLock { _failure = newValue } }
    }
    var healthy: Bool {
        get { lock.withLock { _healthy } }
        set { lock.withLock { _healthy = newValue } }
    }
    var fetches: Int { lock.withLock { _fetches } }
    /// Held closed: fetches wait until it opens (``AsyncGate/unlock()``).
    var gate: AsyncGate? {
        get { lock.withLock { _gate } }
        set { lock.withLock { _gate = newValue } }
    }
    /// Runs inside the health check, before it answers.
    var duringHealthCheck: (@Sendable () async -> Void)? {
        get { lock.withLock { _duringHealthCheck } }
        set { lock.withLock { _duringHealthCheck = newValue } }
    }

    func fetchSignedConfig(currentVersion: Int) async throws -> SignedConfigResponse {
        let gate = lock.withLock { () -> AsyncGate? in
            _fetches += 1
            return _gate
        }
        if let gate {
            await gate.lock()
            gate.unlock()
        }
        if let failure { throw failure }
        return next!
    }

    func fetchConfig(currentVersion: Int) async throws -> CertificateConfig {
        throw PinVaultError.illegalState("a signed block must be served through fetchSignedConfig")
    }

    func healthCheck() async throws -> Bool {
        if let hook = duringHealthCheck { await hook() }
        return healthy
    }

    func downloadHostClientCert(hostname: String) async throws -> Data { Data() }
    func downloadVaultFile(endpoint: String) async throws -> Data { Data() }
    func enroll(token: String?, deviceId: String?, deviceAlias: String?, deviceUid: String?) async throws -> EnrollmentResult {
        EnrollmentResult(p12Bytes: Data())
    }
}
