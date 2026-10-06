import Foundation

/// The backend API PinVault talks to. Implement it to integrate PinVault with
/// any backend; pass it to `PinVault.start(config:configApi:)` (it serves the
/// default block). The library's own HTTP client implements it for every block
/// otherwise. Methods with a Kotlin default body have a default implementation
/// in the extension below; override them by implementing the same signature.
///
/// ## Signed configs
/// ``fetchConfig(currentVersion:)`` returns a parsed config, which nothing can
/// verify. A block with signing keys therefore needs the custom API to adopt
/// ``SignedConfigSource`` as well; PinVault then fetches and verifies the
/// envelope itself. Without it `start` fails for that block unless it called
/// `allowUnsigned()`.
public protocol CertificateConfigApi: Sendable {

    /// Whether the backend is reachable.
    func healthCheck() async throws -> Bool

    /// The latest config. Called for blocks that run unsigned.
    /// - Parameter currentVersion: the version the client holds (0 on the first call).
    func fetchConfig(currentVersion: Int) async throws -> CertificateConfig

    /// Scoped fetch: pins for the intersection of `hosts` and the device's
    /// ACL. Default: drops the extra parameters and calls ``fetchConfig(currentVersion:)``.
    func fetchScopedConfig(currentVersion: Int, hosts: [String]?, deviceId: String?) async throws -> CertificateConfig

    /// A host-specific PKCS12 client certificate for a pin entry with `mtls = true`.
    func downloadHostClientCert(hostname: String) async throws -> Data

    /// A vault file's bytes (legacy; see ``downloadVaultFileWithMeta(endpoint:currentVersion:deviceId:accessToken:)``).
    func downloadVaultFile(endpoint: String) async throws -> Data

    /// A vault file with its metadata (version, encryption, signatures; 304
    /// support). `deviceId` goes in `X-Device-Id`, `accessToken` in
    /// `X-Vault-Token`. Default: wraps ``downloadVaultFile(endpoint:)`` (version 0, `plain`).
    func downloadVaultFileWithMeta(
        endpoint: String,
        currentVersion: Int,
        deviceId: String?,
        accessToken: String?
    ) async throws -> VaultFetchResponse

    /// Registers the device's RSA public key (PEM `PUBLIC KEY`) for
    /// `end_to_end` files. Default: no-op.
    func registerDevicePublicKey(deviceId: String, publicKeyPem: String) async throws

    /// Registers the user-auth RSA public key (`"purpose": "user_auth"`) for
    /// `user_auth` files. `attestationChain` is empty on iOS. Default: no-op.
    func registerUserAuthPublicKey(deviceId: String, publicKeyPem: String, attestationChain: [String]) async throws

    /// Enrollment with a server-generated key (PKCS12). Called only for a block
    /// with `allowServerGeneratedKey()`; other enrollments use `enrollWithCsr`.
    /// Throw ``PinVaultError/enrollmentRefused(httpStatus:serverError:serverMessage:)``
    /// for a refusal, ``PinVaultError/enrollmentPending(requestId:clientId:serverMessage:retryAfterSeconds:verificationCode:)``
    /// when an administrator approves first.
    func enroll(token: String?, deviceId: String?, deviceAlias: String?, deviceUid: String?) async throws -> EnrollmentResult

    /// Enrollment with a CSR over the device's own key (DER PKCS#10). Return
    /// the issued chain (leaf + issuing CA at least); nil = "this backend
    /// cannot take a CSR". `requestId` is set when asking again about a
    /// pending enrollment. Default: nil.
    func enrollWithCsr(
        token: String?,
        deviceId: String?,
        deviceAlias: String?,
        deviceUid: String?,
        csrDer: Data,
        requestId: String?
    ) async throws -> EnrollmentResult?

    /// ``enrollWithCsr(token:deviceId:deviceAlias:deviceUid:csrDer:requestId:)``
    /// with the key's attestation chain (Base64 DER, leaf first; empty on iOS).
    /// Default: drops the chain.
    func enrollWithCsr(
        token: String?,
        deviceId: String?,
        deviceAlias: String?,
        deviceUid: String?,
        csrDer: Data,
        requestId: String?,
        attestationChain: [String]
    ) async throws -> EnrollmentResult?

    /// The seven-argument `enrollWithCsr` with an integrity token bound to the
    /// request (see ``IntegrityTokenProvider``): what PinVault calls. Default: drops the token.
    func enrollWithCsr(
        token: String?,
        deviceId: String?,
        deviceAlias: String?,
        deviceUid: String?,
        csrDer: Data,
        requestId: String?,
        attestationChain: [String],
        integrityToken: String?
    ) async throws -> EnrollmentResult?

    /// Renews the client certificate of a CSR-enrolled device: over the
    /// block's own connection (`recoveryUrl` nil) or, for an expired/refused
    /// certificate, over `recoveryUrl` without a client certificate.
    /// Default: ``ClientCertRenewalResponse/unsupported``.
    func renewClientCert(clientId: String, csrDer: Data, recoveryUrl: String?) async throws -> ClientCertRenewalResponse

    /// Reports a vault file download (fire-and-forget). Default: no-op.
    func reportVaultDownload(_ report: VaultDownloadReport) async throws
}

extension CertificateConfigApi {

    public func fetchScopedConfig(currentVersion: Int, hosts: [String]?, deviceId: String?) async throws -> CertificateConfig {
        try await fetchConfig(currentVersion: currentVersion)
    }

    public func downloadVaultFileWithMeta(
        endpoint: String,
        currentVersion: Int,
        deviceId: String?,
        accessToken: String?
    ) async throws -> VaultFetchResponse {
        // Plain bytes with version 0 — enough for tests and backends without the endpoint.
        let bytes = try await downloadVaultFile(endpoint: endpoint)
        return VaultFetchResponse(content: bytes, version: 0, encryption: "plain")
    }

    public func registerDevicePublicKey(deviceId: String, publicKeyPem: String) async throws {}

    public func registerUserAuthPublicKey(deviceId: String, publicKeyPem: String, attestationChain: [String]) async throws {}

    public func enrollWithCsr(
        token: String?,
        deviceId: String?,
        deviceAlias: String?,
        deviceUid: String?,
        csrDer: Data,
        requestId: String?
    ) async throws -> EnrollmentResult? {
        nil
    }

    public func enrollWithCsr(
        token: String?,
        deviceId: String?,
        deviceAlias: String?,
        deviceUid: String?,
        csrDer: Data,
        requestId: String?,
        attestationChain: [String]
    ) async throws -> EnrollmentResult? {
        try await enrollWithCsr(
            token: token, deviceId: deviceId, deviceAlias: deviceAlias, deviceUid: deviceUid,
            csrDer: csrDer, requestId: requestId
        )
    }

    public func enrollWithCsr(
        token: String?,
        deviceId: String?,
        deviceAlias: String?,
        deviceUid: String?,
        csrDer: Data,
        requestId: String?,
        attestationChain: [String],
        integrityToken: String?
    ) async throws -> EnrollmentResult? {
        try await enrollWithCsr(
            token: token, deviceId: deviceId, deviceAlias: deviceAlias, deviceUid: deviceUid,
            csrDer: csrDer, requestId: requestId, attestationChain: attestationChain
        )
    }

    public func renewClientCert(clientId: String, csrDer: Data, recoveryUrl: String?) async throws -> ClientCertRenewalResponse {
        .unsupported
    }

    public func reportVaultDownload(_ report: VaultDownloadReport) async throws {}

    // Kotlin default arguments, as convenience overloads.

    public func fetchScopedConfig(currentVersion: Int) async throws -> CertificateConfig {
        try await fetchScopedConfig(currentVersion: currentVersion, hosts: nil, deviceId: nil)
    }

    public func downloadVaultFileWithMeta(endpoint: String) async throws -> VaultFetchResponse {
        try await downloadVaultFileWithMeta(endpoint: endpoint, currentVersion: 0, deviceId: nil, accessToken: nil)
    }

    public func renewClientCert(clientId: String, csrDer: Data) async throws -> ClientCertRenewalResponse {
        try await renewClientCert(clientId: clientId, csrDer: csrDer, recoveryUrl: nil)
    }
}
