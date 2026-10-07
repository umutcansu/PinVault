import Foundation

/// The library's own ``CertificateConfigApi`` over the block's pinned
/// bootstrap session (Kotlin `DefaultCertificateConfigApi`, Retrofit/OkHttp).
///
/// All endpoint paths are configurable. With a signing key configured, config
/// responses must be signed envelopes that pass ``SignatureTrust`` (one or
/// more trusted ECDSA-SHA256 signatures, optionally carrying a signing-key set).
///
/// The updater asks a signed block for the envelope itself
/// (``SignedConfigSource``) and verifies it with the same
/// ``SignedConfigVerifier``, so it can keep the envelope next to the stored
/// config; ``fetchConfig(currentVersion:)`` and ``fetchScopedConfig(currentVersion:hosts:deviceId:)``
/// verify too, for callers that only want the config.
///
/// Every body is read with a ceiling (``BoundedBody``), and every request asks
/// for `forbidden-as-409` (PORTING.md §4): an mTLS listener's 403 reaches this
/// client (and ``ReenrollRequiredInterceptor``) as a 403.
final class DefaultCertificateConfigApi: CertificateConfigApi, SignedConfigSource, @unchecked Sendable {

    private static let log = PinVaultLog.tag("DefaultCertificateConfigApi")

    let configUrl: String
    let configEndpoint: String
    let healthEndpoint: String
    let clientCertEndpoint: String
    let enrollmentEndpoint: String
    let vaultReportEndpoint: String
    private let bootstrapPins: [HostPin]
    private let sslManager: DynamicSSLManager
    /// The block's P12 password; host client certificates are re-wrapped to it.
    private let clientKeyPassword: String?
    /// Base URL for first enrollment (a TLS listener); nil = ``configUrl``.
    private let enrollmentUrl: String?
    /// Told the server's reason whenever any request here is refused with
    /// `403 reenroll_required` (a revoked identity), see ``ReenrollRequiredInterceptor``.
    private let onReenrollRequired: (@Sendable (_ reason: String, _ presented: X509Certificate?) -> Void)?
    /// The block's `allowUnpinnedConfigApi()`: no bootstrap pins and plain HTTP are accepted.
    private let allowUnpinned: Bool
    /// The block's `allowServerGeneratedKey()`: only then does a CSR enrollment advertise `p12password`.
    private let allowServerGeneratedKey: Bool
    /// The most a config (or any JSON answer parsed like Retrofit's) may be; tests lower it.
    private let configBodyLimit: Int64
    /// The most a vault file download may be; tests lower it.
    private let vaultBodyLimit: Int64

    /// Nil = the block runs unsigned (`allowUnsigned()`).
    private let trust: SignatureTrust?
    private let verifier: SignedConfigVerifier?

    /// The pinned client every call here goes through. Its handshakes present
    /// the SSL manager's current client identity; after a change (enroll,
    /// renew, unenroll) ``rebuildBootstrapClient()`` still drops the
    /// connections opened with the old one.
    private let bootstrap: Locked<PinnedSession?> = Locked(nil)
    /// How many bootstrap clients were built (tests).
    var bootstrapBuilds: Int { bootstrapBuildCount.get() }
    private let bootstrapBuildCount = Locked(0)

    init(
        configUrl: String,
        configEndpoint: String = PinVaultConfig.defaultConfigEndpoint,
        healthEndpoint: String = PinVaultConfig.defaultHealthEndpoint,
        clientCertEndpoint: String = PinVaultConfig.defaultClientCertEndpoint,
        enrollmentEndpoint: String = PinVaultConfig.defaultEnrollmentEndpoint,
        vaultReportEndpoint: String = PinVaultConfig.defaultVaultReportEndpoint,
        signaturePublicKey: String? = nil,
        bootstrapPins: [HostPin],
        sslManager: DynamicSSLManager,
        signatureTrust: SignatureTrust? = nil,
        clientKeyPassword: String? = nil,
        enrollmentUrl: String? = nil,
        onReenrollRequired: (@Sendable (_ reason: String, _ presented: X509Certificate?) -> Void)? = nil,
        serverScope: String? = nil,
        allowUnpinned: Bool = false,
        allowServerGeneratedKey: Bool = false,
        configBodyLimit: Int64 = BoundedBody.configMaxBytes,
        vaultBodyLimit: Int64 = BoundedBody.vaultMaxBytes
    ) {
        self.configUrl = configUrl
        self.configEndpoint = configEndpoint
        self.healthEndpoint = healthEndpoint
        self.clientCertEndpoint = clientCertEndpoint
        self.enrollmentEndpoint = enrollmentEndpoint
        self.vaultReportEndpoint = vaultReportEndpoint
        self.bootstrapPins = bootstrapPins
        self.sslManager = sslManager
        self.clientKeyPassword = clientKeyPassword
        self.enrollmentUrl = enrollmentUrl
        self.onReenrollRequired = onReenrollRequired
        self.allowUnpinned = allowUnpinned
        self.allowServerGeneratedKey = allowServerGeneratedKey
        self.configBodyLimit = configBodyLimit
        self.vaultBodyLimit = vaultBodyLimit
        let trust = signatureTrust ?? signaturePublicKey.map { SignatureTrust.single(configApiId: "default", key: $0) }
        self.trust = trust
        self.verifier = trust.map { SignedConfigVerifier(trust: $0, serverScope: serverScope) }
        bootstrap.set(newBootstrapClient())
    }

    private func newBootstrapClient() -> PinnedSession {
        bootstrapBuildCount.withLock { $0 += 1 }
        return sslManager.buildBootstrapClient(
            bootstrapPins,
            interceptor: onReenrollRequired.map { ReenrollRequiredInterceptor(onReenrollRequired: $0) },
            allowUnpinned: allowUnpinned,
            forbiddenAs409: .always
        )
    }

    /// The bootstrap client requests go through now.
    var bootstrapClient: PinnedSession {
        bootstrap.get()!
    }

    /// Swaps in a fresh pinned client, so no request rides a connection made with the previous identity.
    func rebuildBootstrapClient() {
        let fresh = newBootstrapClient()
        let old = bootstrap.withLock { slot -> PinnedSession? in
            defer { slot = fresh }
            return slot
        }
        // Idle connections close; requests in flight on the old client finish.
        if let transport = old?.transport as? InterceptedTransport, let base = transport.base as? URLSessionTransport {
            base.retireSessions()
        } else if let base = old?.transport as? URLSessionTransport {
            base.retireSessions()
        }
        Self.log.d("Bootstrap client rebuilt")
    }

    // MARK: Plumbing

    /// One request through the bootstrap client, its body read under `limit`.
    private func send(_ request: URLRequest, _ limit: BoundedBody.Limit, client: PinnedSession? = nil) async throws -> PinnedResponse {
        try await (client ?? bootstrapClient).send(PinnedExchange(request: request, bodyLimit: limit))
    }

    /// Retrofit's `@Url` resolution: `endpoint` against ``configUrl``, then the query.
    private func resolve(_ endpoint: String, query: [(String, String?)] = []) throws -> URL {
        guard let base = URL(string: configUrl), let resolved = URL(string: endpoint, relativeTo: base)?.absoluteURL,
              var components = URLComponents(url: resolved, resolvingAgainstBaseURL: false) else {
            throw PinVaultError.illegalArgument("Cannot build a URL from \(configUrl) and \(endpoint)")
        }
        let items = query.compactMap { name, value in value.map { URLQueryItem(name: name, value: $0) } }
        if !items.isEmpty { components.queryItems = (components.queryItems ?? []) + items }
        guard let url = components.url else {
            throw PinVaultError.illegalArgument("Cannot build a URL from \(configUrl) and \(endpoint)")
        }
        return url
    }

    /// OkHttp's `"$base$path"`: plain concatenation.
    private func concat(_ base: String, _ path: String) throws -> URL {
        guard let url = URL(string: base + path) else { throw PinVaultError.illegalArgument("Invalid URL: \(base)\(path)") }
        return url
    }

    private static func request(_ url: URL, method: String = "GET", headers: [String: String?] = [:], json: Data? = nil) -> URLRequest {
        var request = URLRequest(url: url)
        request.httpMethod = method
        for (name, value) in headers {
            if let value { request.setValue(value, forHTTPHeaderField: name) }
        }
        if let json {
            request.setValue("application/json; charset=utf-8", forHTTPHeaderField: "Content-Type")
            request.httpBody = json
        }
        return request
    }

    /// A Retrofit-style GET of JSON: a non-2xx status is an ``HttpException``.
    private func getJSON(_ endpoint: String, query: [(String, String?)] = [], headers: [String: String?] = [:]) async throws -> Data {
        let request = Self.request(try resolve(endpoint, query: query), headers: headers)
        let response = try await send(request, BoundedBody.Limit(maxBytes: configBodyLimit, what: "config"))
        guard (200..<300).contains(response.statusCode) else { throw HttpException(response) }
        return response.data
    }

    private func decode<T: Decodable>(_ type: T.Type, _ data: Data) throws -> T {
        do {
            return try JSONDecoder().decode(type, from: data)
        } catch let error as PinVaultError {
            throw error
        } catch {
            throw JsonSyntaxException(message: Self.describe(error))
        }
    }

    private static func describe(_ error: any Error) -> String {
        guard let decoding = error as? DecodingError else { return "\(error)" }
        switch decoding {
        case .dataCorrupted(let context), .keyNotFound(_, let context), .typeMismatch(_, let context), .valueNotFound(_, let context):
            let path = context.codingPath.map(\.stringValue).joined(separator: ".")
            return path.isEmpty ? context.debugDescription : "\(context.debugDescription) at \(path)"
        @unknown default:
            return "\(error)"
        }
    }

    private static func features(_ features: String) -> [String: String?] {
        [ForbiddenAsConflict.featuresHeader: features]
    }

    // MARK: Config

    func healthCheck() async throws -> Bool {
        do {
            let data = try await getJSON(healthEndpoint)
            let object = try JSONSerialization.jsonObject(with: data) as? [String: Any]
            let isHealthy = JSONText.gsonString(object?["status"]) == "ok"
            Self.log.d("Health check: \(isHealthy ? "ok" : "unhealthy")")
            return isHealthy
        } catch {
            Self.log.e("Health check failed", error)
            return false
        }
    }

    func fetchConfig(currentVersion: Int) async throws -> CertificateConfig {
        guard let verifier else {
            Self.log.w(
                "Config signature verification DISABLED — config integrity cannot be guaranteed. " +
                    "Set signaturePublicKey in PinVaultConfig for production use."
            )
            return try decode(CertificateConfig.self, try await getJSON(configEndpoint, query: [("currentVersion", String(currentVersion))]))
        }
        let signed = try await fetchSignedConfig(currentVersion: currentVersion)
        // The key set riding along goes first: the config in the same response
        // may already be signed by a key that set introduces.
        try verifier.applyKeySet(signed)
        return try verifier.verifyFetched(signed).config
    }

    /// The signed envelope as served, unverified — the caller verifies it (``SignedConfigVerifier``).
    func fetchSignedConfig(currentVersion: Int) async throws -> SignedConfigResponse {
        let data = try await getJSON(
            configEndpoint, query: [("currentVersion", String(currentVersion))], headers: Self.features(Self.signedConfigFeatures)
        )
        return try decode(SignedConfigResponse.self, data)
    }

    func fetchScopedSignedConfig(currentVersion: Int, hosts: [String]?, deviceId: String?) async throws -> SignedConfigResponse {
        let hostsParam = hosts.flatMap { $0.isEmpty ? nil : $0.joined(separator: ",") }
        guard hostsParam != nil || deviceId != nil else { return try await fetchSignedConfig(currentVersion: currentVersion) }
        var headers = Self.features(Self.signedConfigFeatures)
        headers["X-Device-Id"] = deviceId
        let data = try await getJSON(
            configEndpoint, query: [("currentVersion", String(currentVersion)), ("hosts", hostsParam)], headers: headers
        )
        return try decode(SignedConfigResponse.self, data)
    }

    /// Scoped config fetch: `?hosts=a,b,c` and/or `X-Device-Id`, so the server
    /// can filter pins per the device's ACL.
    func fetchScopedConfig(currentVersion: Int, hosts: [String]?, deviceId: String?) async throws -> CertificateConfig {
        let hostsParam = hosts.flatMap { $0.isEmpty ? nil : $0.joined(separator: ",") }
        guard let verifier else {
            Self.log.w("Config signature verification DISABLED (scoped fetch)")
            guard hostsParam != nil || deviceId != nil else {
                return try decode(CertificateConfig.self, try await getJSON(configEndpoint, query: [("currentVersion", String(currentVersion))]))
            }
            let data = try await getJSON(
                configEndpoint,
                query: [("currentVersion", String(currentVersion)), ("hosts", hostsParam)],
                headers: ["X-Device-Id": deviceId]
            )
            return try decode(CertificateConfig.self, data)
        }
        let signed = try await fetchScopedSignedConfig(currentVersion: currentVersion, hosts: hosts, deviceId: deviceId)
        try verifier.applyKeySet(signed)
        return try verifier.verifyFetched(signed) { detail in
            "Config signature verification failed (scoped fetch).\(detail)"
        }.config
    }

    // MARK: Host client certificates

    /// The host's client certificate, wrapped with this block's
    /// ``clientKeyPassword``: a server that sends a one-off password
    /// (`X-P12-Password`) gets its bundle re-wrapped here, so the app never
    /// needs a password chosen on the server.
    func downloadHostClientCert(hostname: String) async throws -> Data {
        let url = "\(clientCertEndpoint)/\(hostname)/download"
        Self.log.d("Downloading host client cert: \(url)")
        let request = Self.request(try resolve(url), headers: Self.features(P12Rewrap.feature))
        let response = try await send(request, BoundedBody.Limit(maxBytes: BoundedBody.smallMaxBytes, what: "host client certificate"))
        guard (200..<300).contains(response.statusCode) else { throw HttpException(response) }
        let bytes = response.data
        if bytes.isEmpty, response.http?.expectedContentLength == 0 {
            throw Exception(message: "Empty host client certificate response")
        }
        if let oneOff = response.http?.value(forHTTPHeaderField: P12Rewrap.passwordHeader), let clientKeyPassword {
            return try P12Rewrap.rewrap(bytes, from: oneOff, to: clientKeyPassword)
        }
        return bytes
    }

    // MARK: Vault files

    func downloadVaultFile(endpoint: String) async throws -> Data {
        Self.log.d("Downloading vault file: \(endpoint)")
        let response = try await send(Self.request(try resolve(endpoint)), BoundedBody.Limit(maxBytes: vaultBodyLimit, what: "vault file"))
        guard (200..<300).contains(response.statusCode) else { throw HttpException(response) }
        return response.data
    }

    /// V2 download with full HTTP metadata: `?version=N` (304 support),
    /// `X-Device-Id`, `X-Vault-Token`; reads `X-Vault-Version`,
    /// `X-Vault-Encryption` and the signature headers (v1 and v2). A refusal
    /// throws ``VaultFetchHttpException`` with the status and the first 200
    /// characters of the body.
    func downloadVaultFileWithMeta(
        endpoint: String,
        currentVersion: Int,
        deviceId: String?,
        accessToken: String?
    ) async throws -> VaultFetchResponse {
        Self.log.d("Downloading vault file (meta): \(endpoint) v=\(currentVersion)")
        let path = endpoint.contains("?") ? "\(endpoint)&version=\(currentVersion)" : "\(endpoint)?version=\(currentVersion)"
        let request = Self.request(try concat(configUrl, path), headers: ["X-Device-Id": deviceId, "X-Vault-Token": accessToken])
        let response = try await send(request, BoundedBody.Limit(maxBytes: vaultBodyLimit, what: "vault file"))
        let header = { (name: String) in response.http?.value(forHTTPHeaderField: name) }
        let version = header("X-Vault-Version").flatMap { Int($0) } ?? currentVersion
        let encryption = header("X-Vault-Encryption") ?? "plain"

        if response.statusCode == 304 {
            return VaultFetchResponse(content: Data(), version: version, encryption: encryption, notModified: true)
        }
        guard (200..<300).contains(response.statusCode) else {
            // Quoted, never parsed whole: a long error body is cut, not refused.
            throw VaultFetchHttpException(code: response.statusCode, body: BoundedBody.prefixText(response.data, 200))
        }
        return VaultFetchResponse(
            content: response.data,
            version: version,
            encryption: encryption,
            notModified: false,
            signature: header("X-Vault-Signature"),
            signatures: header("X-Vault-Signatures").map(Self.parseSignaturesHeader),
            signatureV2: header(Self.vaultSignatureV2Header),
            signaturesV2: header(Self.vaultSignaturesV2Header).map(Self.parseSignaturesHeader)
        )
    }

    /// `X-Vault-Signatures: <keyId>:<signature>, <keyId>:<signature>` — one
    /// entry per signing key. Base64 never contains `:` or `,`, so the split is
    /// unambiguous; an entry without a key id is just the signature.
    static func parseSignaturesHeader(_ value: String) -> [SignatureEntry] {
        value.split(separator: ",", omittingEmptySubsequences: false)
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
            .map { entry in
                guard let colon = entry.firstIndex(of: ":") else { return SignatureEntry(signature: entry) }
                return SignatureEntry(keyId: String(entry[..<colon]), signature: String(entry[entry.index(after: colon)...]))
            }
    }

    // MARK: Device keys

    /// Registers the device's RSA public key for `end_to_end` files, with the
    /// algorithm iOS keys use (``DeviceKeys/registrationAlgorithm``).
    func registerDevicePublicKey(deviceId: String, publicKeyPem: String) async throws {
        try await registerDevicePublicKey(deviceId: deviceId, publicKeyPem: publicKeyPem, proof: nil)
    }

    /// Registers the device's RSA public key, with `proof` when the router has
    /// one: over a TLS listener the server keeps the first key it was given
    /// and replaces it only for a request that carries the device's token for
    /// an end_to_end file (`X-Vault-Key` + `X-Vault-Token`). Over mTLS the
    /// client certificate is the proof and the headers are ignored.
    /// - Parameter algorithm: what the key provider names (L4: `RSA-OAEP-SHA256-MGF1-SHA256`).
    func registerDevicePublicKey(
        deviceId: String,
        publicKeyPem: String,
        proof: DeviceKeyProof?,
        algorithm: String = DeviceKeys.registrationAlgorithm
    ) async throws {
        try await registerKey(deviceId, publicKeyPem, proof, purpose: nil, attestationChain: [], algorithm: algorithm)
    }

    /// Registers the device's user-auth key (`purpose: user_auth`), which `user_auth` files are sealed for.
    func registerUserAuthPublicKey(deviceId: String, publicKeyPem: String, attestationChain: [String]) async throws {
        try await registerUserAuthPublicKey(deviceId: deviceId, publicKeyPem: publicKeyPem, attestationChain: attestationChain, proof: nil)
    }

    /// ``registerUserAuthPublicKey(deviceId:publicKeyPem:attestationChain:)``
    /// with the same proof rules as ``registerDevicePublicKey(deviceId:publicKeyPem:proof:algorithm:)``.
    /// A non-empty `attestationChain` goes along as `attestationChain` (older
    /// servers ignore it). The server's refusals become a
    /// ``UserAuthKeyRefusedException`` that says what to do.
    func registerUserAuthPublicKey(
        deviceId: String,
        publicKeyPem: String,
        attestationChain: [String],
        proof: DeviceKeyProof?,
        algorithm: String = DeviceKeys.registrationAlgorithm
    ) async throws {
        try await registerKey(deviceId, publicKeyPem, proof, purpose: Self.userAuthKeyPurpose, attestationChain: attestationChain, algorithm: algorithm)
    }

    private func registerKey(
        _ deviceId: String,
        _ publicKeyPem: String,
        _ proof: DeviceKeyProof?,
        purpose: String?,
        attestationChain: [String],
        algorithm: String
    ) async throws {
        var json: [String: Any] = ["publicKeyPem": publicKeyPem, "algorithm": algorithm]
        if let purpose { json["purpose"] = purpose }
        if !attestationChain.isEmpty { json["attestationChain"] = attestationChain }
        let request = Self.request(
            try concat(configUrl, "api/v1/vault/devices/\(deviceId)/public-key"),
            method: "POST",
            headers: ["X-Vault-Key": proof?.vaultKey, "X-Vault-Token": proof?.token],
            json: try Self.jsonBody(json)
        )
        let response = try await send(request, BoundedBody.Limit(
            maxBytes: BoundedBody.smallMaxBytes, what: "key registration", prefixBytes: Int(BoundedBody.smallMaxBytes),
            readWhole: { _ in false }
        ))
        let code = response.statusCode
        let success = (200..<300).contains(code)
        if !success, purpose == Self.userAuthKeyPurpose, code == 409 || code == 403 {
            let answer = Self.jsonObject(response.data)
            if let refusal = UserAuthKeyRefusedException.from(
                httpStatus: code,
                error: answer.flatMap { Self.optString($0, "error").nonBlank },
                reason: answer.flatMap { Self.optString($0, "reason").nonBlank },
                sentChain: !attestationChain.isEmpty
            ) {
                throw refusal
            }
        }
        switch code {
        case _ where success:
            Self.log.d("Registered device \(purpose ?? "E2E") key (attestation chain: \(attestationChain.count))")
        case 409:
            throw Exception(message:
                "Device public key registration refused (HTTP 409): another key is registered for this device; " +
                    "replacing it needs the device's token for an end_to_end or user_auth file, or an administrator reset"
            )
        case 403:
            throw Exception(message: "Device public key registration refused (HTTP 403): the client certificate does not belong to this device")
        default:
            throw Exception(message: "Device public key registration failed: HTTP \(code)")
        }
    }

    // MARK: Enrollment

    func enroll(token: String?, deviceId: String?, deviceAlias: String?, deviceUid: String?) async throws -> EnrollmentResult {
        try await enrollRequest(token, deviceId, deviceAlias, deviceUid, csrDer: nil, requestId: nil, attestationChain: [], integrityToken: nil)
    }

    /// Sends the CSR along with the usual enrollment fields and the `csr`
    /// feature. A server that understands it answers with a PEM chain
    /// (`X-PinVault-Cert-Format: pem-chain`); an older server ignores both and
    /// answers with a P12 exactly as for ``enroll(token:deviceId:deviceAlias:deviceUid:)``.
    /// With `requestId` the device asks again whether the enrollment it was
    /// told to wait for (HTTP 202) has been approved.
    func enrollWithCsr(
        token: String?, deviceId: String?, deviceAlias: String?, deviceUid: String?, csrDer: Data, requestId: String?
    ) async throws -> EnrollmentResult? {
        try await enrollRequest(token, deviceId, deviceAlias, deviceUid, csrDer: csrDer, requestId: requestId, attestationChain: [], integrityToken: nil)
    }

    /// The CSR enrollment with the key's attestation chain (`"attestationChain": ["<base64 DER>", …]`, leaf first).
    func enrollWithCsr(
        token: String?, deviceId: String?, deviceAlias: String?, deviceUid: String?, csrDer: Data, requestId: String?,
        attestationChain: [String]
    ) async throws -> EnrollmentResult? {
        try await enrollRequest(
            token, deviceId, deviceAlias, deviceUid, csrDer: csrDer, requestId: requestId, attestationChain: attestationChain, integrityToken: nil
        )
    }

    /// The CSR enrollment with an integrity token bound to the request (`"integrityToken"`).
    func enrollWithCsr(
        token: String?, deviceId: String?, deviceAlias: String?, deviceUid: String?, csrDer: Data, requestId: String?,
        attestationChain: [String], integrityToken: String?
    ) async throws -> EnrollmentResult? {
        try await enrollRequest(
            token, deviceId, deviceAlias, deviceUid, csrDer: csrDer, requestId: requestId,
            attestationChain: attestationChain, integrityToken: integrityToken
        )
    }

    /// What an enrollment request advertises (before `forbidden-as-409`). The
    /// P12 path asks for a one-off P12 password; a CSR enrollment asks for a
    /// chain, and adds `p12password` only when the block would accept a server-made key.
    func enrollmentFeatures(csr: Bool) -> String {
        if !csr { return P12Rewrap.feature }
        return allowServerGeneratedKey ? "\(P12Rewrap.feature),\(Self.csrFeature)" : Self.csrFeature
    }

    private func enrollRequest(
        _ token: String?,
        _ deviceId: String?,
        _ deviceAlias: String?,
        _ deviceUid: String?,
        csrDer: Data?,
        requestId: String?,
        attestationChain: [String],
        integrityToken: String?
    ) async throws -> EnrollmentResult {
        var json: [String: Any] = [:]
        if let token { json["token"] = token }
        if let deviceId { json["deviceId"] = deviceId }
        if let deviceAlias { json["deviceAlias"] = deviceAlias }
        if let deviceUid { json["deviceUid"] = deviceUid }
        if let csrDer { json["csr"] = Base64.encode(csrDer) }
        if let requestId { json["requestId"] = requestId }
        if csrDer != nil, !attestationChain.isEmpty { json["attestationChain"] = attestationChain }
        // Bound to this CSR by its request hash; meaningless without one.
        if csrDer != nil, let integrityToken, !integrityToken.isBlank { json["integrityToken"] = integrityToken }

        let request = Self.request(
            try concat(enrollmentUrl ?? configUrl, enrollmentEndpoint),
            method: "POST",
            headers: Self.features(enrollmentFeatures(csr: csrDer != nil)),
            json: try Self.jsonBody(json)
        )
        // A P12 or a PEM chain: neither is large. Refusal and 202 bodies are read
        // as far as they go; one that does not fit simply does not parse.
        let response = try await send(request, BoundedBody.Limit(
            maxBytes: BoundedBody.smallMaxBytes, what: "enrollment", prefixBytes: Int(BoundedBody.smallMaxBytes),
            readWhole: { (200..<300).contains($0) && $0 != 202 }
        ))
        let code = response.statusCode
        // Taken, but an administrator approves the device first (an enrollment
        // code whose policy asks for it): no certificate yet, a request id.
        if code == 202 {
            let answer = Self.jsonObject(response.data)
            guard let id = answer.flatMap({ Self.optString($0, "requestId").nonBlank }) else {
                throw Exception(message: "Enrollment answered 202 without a requestId")
            }
            throw PinVaultError.enrollmentPending(
                requestId: id,
                clientId: answer.flatMap { Self.optString($0, "clientId").nonBlank },
                serverMessage: answer.flatMap { Self.optString($0, "message").nonBlank },
                retryAfterSeconds: response.http?.value(forHTTPHeaderField: "Retry-After")
                    .flatMap { Int($0.trimmingCharacters(in: .whitespaces)) }
            )
        }
        guard (200..<300).contains(code) else {
            // A refusal carries its reason in the body (`device_already_enrolled`,
            // `revoked`, …); keep it, the app shows it to the user.
            if (400...499).contains(code) {
                let answer = Self.jsonObject(response.data)
                throw PinVaultError.enrollmentRefused(
                    httpStatus: code,
                    serverError: answer.flatMap { Self.optString($0, "error").nonBlank },
                    // An attestation refusal says why in `reason`.
                    serverMessage: answer.flatMap { Self.optString($0, "message").nonBlank ?? Self.optString($0, "reason").nonBlank }
                )
            }
            throw Exception(message: "Enrollment failed — HTTP \(code)")
        }
        let body = response.data
        if body.isEmpty, response.http?.expectedContentLength == 0 {
            throw Exception(message: "Empty enrollment response")
        }
        if response.http?.value(forHTTPHeaderField: Self.certFormatHeader) == Self.certFormatPemChain {
            let chain = try Self.parseChainResponse(String(decoding: body, as: UTF8.self))
            Self.log.d("Enrollment successful — certificate chain of \(chain.count)")
            return EnrollmentResult(p12Bytes: Data(), p12Hash: nil, p12Password: nil, certificateChainPem: chain)
        }
        Self.log.d("Enrollment successful — \(body.count) bytes")
        return EnrollmentResult(
            p12Bytes: body,
            p12Hash: response.http?.value(forHTTPHeaderField: "X-P12-SHA256"),
            p12Password: response.http?.value(forHTTPHeaderField: P12Rewrap.passwordHeader)
        )
    }

    /// `POST <base><clientCertEndpoint>/renew` with the CSR. Over the block's
    /// own client the presented certificate identifies the device; over
    /// `recoveryUrl` (no client certificate) the body's `clientId` does, and
    /// the server checks the CSR signature against the key it registered.
    func renewClientCert(clientId: String, csrDer: Data, recoveryUrl: String?) async throws -> ClientCertRenewalResponse {
        let request = Self.request(
            try concat(recoveryUrl ?? configUrl, "\(clientCertEndpoint)/renew"),
            method: "POST",
            headers: Self.features(Self.csrFeature),
            json: try Self.jsonBody(["clientId": clientId, "csr": Base64.encode(csrDer)])
        )
        let response = try await send(request, .always(BoundedBody.smallMaxBytes, "certificate renewal"))
        let body = BoundedBody.text(response.data, response.response)
        switch response.statusCode {
        case 200:
            return .issued(certificateChainPem: try Self.parseChainResponse(body))
        case 403:
            let answer = Self.jsonObject(response.data)
            let error = answer.map { Self.optString($0, "error") }
            if error == Self.reenrollRequired {
                let reason = answer.flatMap { Self.optString($0, "message").nonBlank }
                return .reenrollRequired(reason: reason ?? Self.reenrollRequired)
            }
            throw Exception(message: "Certificate renewal refused — HTTP 403 \(error ?? "")")
        case 404, 405:
            return .unsupported
        default:
            throw Exception(message: "Certificate renewal failed — HTTP \(response.statusCode)")
        }
    }

    static func parseChainResponse(_ body: String) throws -> [String] {
        guard let object = jsonObject(Data(body.utf8)) else {
            throw Exception(message: "Certificate response is not a JSON object")
        }
        guard let array = object["chain"] as? [Any] else { throw Exception(message: "Certificate response has no chain") }
        let chain = try array.enumerated().map { index, element -> String in
            guard let text = element as? String else { throw Exception(message: "Certificate response: chain[\(index)] is not a string") }
            return text
        }
        if chain.isEmpty { throw Exception(message: "Certificate response has an empty chain") }
        return chain
    }

    // MARK: Reports

    func reportVaultDownload(_ report: VaultDownloadReport) async throws {
        do {
            var json: [String: Any] = [
                "key": report.key, "version": report.version, "status": report.status,
                "deviceManufacturer": report.deviceManufacturer, "deviceModel": report.deviceModel,
                "enrollmentLabel": report.enrollmentLabel, "deviceId": report.deviceId, "deviceAlias": report.deviceAlias,
            ]
            if let failureReason = report.failureReason { json["failureReason"] = failureReason }
            if let authMethod = report.authMethod { json["authMethod"] = authMethod }
            var request = Self.request(try concat(configUrl, vaultReportEndpoint), method: "POST", json: try Self.jsonBody(json))
            // A short leash: the report never holds anything up.
            request.timeoutInterval = 5
            _ = try await send(request, .prefix(BoundedBody.errorPrefixBytes))
            Self.log.d("Vault report sent: \(report.key) → \(report.status)")
        } catch {
            Self.log.e("Failed to report vault download: \(report.key)", error)
        }
    }

    // MARK: Attestation (ATTESTATION.md §2)

    /// `GET <configUrl>api/v1/attest/challenge`: the nonce of an attestation
    /// round, as the server sent it (`nonce`, `expiresIn`, `serverTime`).
    /// - Throws: ``AttestationHttpException`` for any non-2xx answer.
    func attestChallenge() async throws -> [String: Any] {
        let response = try await send(Self.request(try concat(configUrl, Self.attestChallengeEndpoint)), .always(BoundedBody.smallMaxBytes, "attestation challenge"))
        let body = BoundedBody.text(response.data, response.response)
        guard (200..<300).contains(response.statusCode) else { throw AttestationHttpException.of(httpStatus: response.statusCode, body: body) }
        return try Self.parseAttestJson(body, "challenge")
    }

    /// `POST <configUrl>api/v1/attest` with the signed report and returns the
    /// server's verdict as it came — `result`, `arc`, `token`, `config`, …
    /// - Throws: ``AttestationHttpException`` for any non-2xx answer, with the
    ///   server's `error` and its `message` or `reason`.
    func attest(_ body: Data) async throws -> [String: Any] {
        let request = Self.request(try concat(configUrl, Self.attestEndpoint), method: "POST", json: body)
        let response = try await send(request, .always(BoundedBody.smallMaxBytes, "attestation"))
        let answer = BoundedBody.text(response.data, response.response)
        guard (200..<300).contains(response.statusCode) else { throw AttestationHttpException.of(httpStatus: response.statusCode, body: answer) }
        return try Self.parseAttestJson(answer, "attest")
    }

    private static func parseAttestJson(_ body: String, _ what: String) throws -> [String: Any] {
        guard let object = jsonObject(Data(body.utf8)) else {
            throw Exception(message: "The attestation \(what) answer is not JSON (\(body.kotlinTake(80)))")
        }
        return object
    }

    // MARK: JSON helpers (org.json semantics)

    static func jsonBody(_ object: [String: Any]) throws -> Data {
        try JSONSerialization.data(withJSONObject: object, options: [.withoutEscapingSlashes])
    }

    /// The JSON object in `data`, or nil when it is not one (`runCatching { JSONObject(body) }`).
    static func jsonObject(_ data: Data) -> [String: Any]? {
        (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
    }

    /// `JSONObject.optString`: "" when absent or null, the value's text otherwise.
    static func optString(_ object: [String: Any], _ key: String) -> String {
        switch object[key] {
        case nil, is NSNull: return ""
        case let string as String: return string
        case let value?:
            if let text = JSONText.gsonString(value) { return text }
            if let data = try? JSONSerialization.data(withJSONObject: value, options: [.withoutEscapingSlashes]) {
                return String(decoding: data, as: UTF8.self)
            }
            return "\(value)"
        }
    }

    // MARK: Wire constants

    /// Sent with every signed-config request so a backend knows what this
    /// client understands: `redelivery` — the same signed config may be served
    /// again (signature caching); `multisig` — the `signatures` field; `keyset`
    /// — signing-key sets. A backend must not rely on any of these without it.
    static let signedConfigFeatures = "redelivery,multisig,keyset"
    /// Feature sent with enrollment and renewal: `csr` — the body carries a
    /// PKCS#10 request over the device's own key, answer with a PEM chain.
    static let csrFeature = "csr"
    /// Response header that marks a certificate-chain answer to a CSR request.
    static let certFormatHeader = "X-PinVault-Cert-Format"
    static let certFormatPemChain = "pem-chain"
    /// The `error` value a server sends when an identity must enroll again.
    static let reenrollRequired = "reenroll_required"
    /// Vault signature headers of the v2 scheme (`pinvault-vault-file:v2:<configApiId>:<key>:<version>:<sha256 hex>`).
    static let vaultSignatureV2Header = "X-Vault-Signature-V2"
    static let vaultSignaturesV2Header = "X-Vault-Signatures-V2"
    /// Device-side attestation endpoints, relative to the block's `configUrl` (`ATTESTATION.md` §2).
    static let attestChallengeEndpoint = "api/v1/attest/challenge"
    static let attestEndpoint = "api/v1/attest"
    /// `purpose` of a user-auth key registration.
    static let userAuthKeyPurpose = "user_auth"
}

// MARK: - Errors (Kotlin exception classes of DefaultCertificateConfigApi.kt and Retrofit)

/// A plain `java.lang.Exception` of the Kotlin code (the type name is what
/// `getClass().getSimpleName()` printed on Android).
struct Exception: Error, Sendable, LocalizedError, CustomStringConvertible {
    let message: String
    var cause: (any Error)? = nil

    var errorDescription: String? { message }
    var description: String { "Exception: \(message)" }
}

/// Retrofit's `HttpException`: a Config API call answered with a non-2xx status.
struct HttpException: Error, Sendable, LocalizedError, CustomStringConvertible {
    let code: Int
    let message: String

    init(code: Int) {
        self.code = code
        self.message = "HTTP \(code) \(HttpException.reasonPhrase(code))"
    }

    init(_ response: PinnedResponse) {
        self.init(code: response.statusCode)
    }

    var errorDescription: String? { message }
    var description: String { "HttpException: \(message)" }

    /// The reason phrase of a status line (`Response.message()`).
    static func reasonPhrase(_ code: Int) -> String {
        let phrases: [Int: String] = [
            400: "Bad Request", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found", 405: "Method Not Allowed",
            408: "Request Timeout", 409: "Conflict", 410: "Gone", 412: "Precondition Failed", 413: "Payload Too Large",
            429: "Too Many Requests", 500: "Internal Server Error", 501: "Not Implemented", 502: "Bad Gateway",
            503: "Service Unavailable", 504: "Gateway Timeout",
        ]
        return phrases[code] ?? HTTPURLResponse.localizedString(forStatusCode: code).capitalized
    }
}

/// Gson's `JsonSyntaxException`: a body that is not the JSON a call expects.
struct JsonSyntaxException: Error, Sendable, LocalizedError, CustomStringConvertible {
    let message: String
    var errorDescription: String? { message }
    var description: String { "JsonSyntaxException: \(message)" }
}

/// A vault download the server refused. The message keeps the
/// `Vault fetch failed: HTTP <code> — <body>` form; `code` and `body` let the
/// router react to `412 user_auth_key_required`.
struct VaultFetchHttpException: Error, Sendable, LocalizedError, CustomStringConvertible {
    let code: Int
    let body: String?
    var message: String { "Vault fetch failed: HTTP \(code) — \(body ?? "null")" }
    var errorDescription: String? { message }
    var description: String { "VaultFetchHttpException: \(message)" }
}

/// The server refused an attestation call. `serverError` is its `error`
/// (`nonce_expired`, `signature_invalid`, `device_revoked`, `key_mismatch`,
/// `attestation_required`, `attestation_invalid`, …), `serverMessage` its
/// `message` or `reason`; both nil when the body was not JSON.
struct AttestationHttpException: Error, Sendable, LocalizedError, CustomStringConvertible {
    let httpStatus: Int
    let serverError: String?
    let serverMessage: String?

    var message: String {
        "Attestation refused — HTTP \(httpStatus)" + (serverError.map { " \($0)" } ?? "") + (serverMessage.map { ": \($0)" } ?? "")
    }

    var errorDescription: String? { message }
    var description: String { "AttestationHttpException: \(message)" }

    static func of(httpStatus: Int, body: String) -> AttestationHttpException {
        let json = DefaultCertificateConfigApi.jsonObject(Data(body.utf8))
        return AttestationHttpException(
            httpStatus: httpStatus,
            serverError: json.flatMap { DefaultCertificateConfigApi.optString($0, "error").nonBlank },
            serverMessage: json.flatMap {
                DefaultCertificateConfigApi.optString($0, "message").nonBlank ?? DefaultCertificateConfigApi.optString($0, "reason").nonBlank
            }
        )
    }
}

/// The server refused the device's user-auth key. The message says what the
/// app (or its operator) has to do; `serverError` is the server's `error`.
struct UserAuthKeyRefusedException: Error, Sendable, LocalizedError, CustomStringConvertible {
    let httpStatus: Int
    let serverError: String
    let message: String

    var errorDescription: String? { message }
    var description: String { "UserAuthKeyRefusedException: \(message)" }

    /// The refusal for a known `error`, or nil to fall back to the generic message.
    static func from(httpStatus: Int, error: String?, reason: String?, sentChain: Bool) -> UserAuthKeyRefusedException? {
        switch error {
        case "user_auth_key_exists":
            return UserAuthKeyRefusedException(
                httpStatus: httpStatus, serverError: "user_auth_key_exists",
                message: "The server keeps another user-auth key for this device (HTTP \(httpStatus) user_auth_key_exists) and " +
                    "replaces it only with a valid key attestation" + (sentChain ? "" : ", which this device could not provide") +
                    ". An administrator must reset this device's user-auth key on the server; then fetch again."
            )
        case "attestation_required":
            return UserAuthKeyRefusedException(
                httpStatus: httpStatus, serverError: "attestation_required",
                message: "The server accepts user-auth keys only with an Android key attestation (HTTP \(httpStatus) " +
                    "attestation_required) and this device sent none: its Keystore could not attest the key."
            )
        case "attestation_invalid":
            return UserAuthKeyRefusedException(
                httpStatus: httpStatus, serverError: "attestation_invalid",
                message: "The server refused this device's key attestation (HTTP \(httpStatus) attestation_invalid)" +
                    (reason.map { ": \($0)" } ?? "") + "."
            )
        default:
            return nil
        }
    }
}

/// Proof that lets a device replace its registered E2E key over a TLS
/// listener: its access token for an end_to_end vault file (`vaultKey` is the
/// server-side key, the last segment of the file's endpoint).
struct DeviceKeyProof: Sendable, Equatable, CustomStringConvertible {
    let vaultKey: String
    let token: String

    /// Never prints the token.
    var description: String { "DeviceKeyProof(vaultKey=\(vaultKey), token=***)" }
}

/// Kotlin's `e.message`, for any error the library reports as a reason.
enum ErrorMessage {
    static func of(_ error: any Error) -> String? {
        switch error {
        case let error as PinVaultError: return error.message
        case let error as LocalizedError where error.errorDescription != nil: return error.errorDescription
        case let error as URLError: return error.localizedDescription
        case is CancellationError: return "Cancelled"
        default: return String(describing: error)
        }
    }
}

extension String {
    /// Kotlin `ifBlank { null }`.
    var nonBlank: String? { isBlank ? nil : self }
}
