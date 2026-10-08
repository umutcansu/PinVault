import Foundation

/// Adopted by a custom ``CertificateConfigApi`` whose backend serves signed
/// configs. PinVault then asks for the envelope instead of a parsed config and
/// verifies it as for its own HTTP client: signatures, `requiredSignatures`,
/// signing-key sets, `issuedAt` / `expiresAt`, replay, `serverScope`.
///
/// ```swift
/// final class MyConfigApi: CertificateConfigApi, SignedConfigSource {
///     func fetchSignedConfig(currentVersion: Int) async throws -> SignedConfigResponse {
///         let body = try await transport.get("pins?current=\(currentVersion)")
///         return SignedConfigResponse(payload: body.payload, signature: body.signature)
///     }
///     // … the CertificateConfigApi methods
/// }
/// ```
///
/// Pass the payload on byte for byte: the signature covers its UTF-8 bytes.
public protocol SignedConfigSource: Sendable {

    /// The signed envelope of the latest config (`currentVersion` 0 on the first call).
    func fetchSignedConfig(currentVersion: Int) async throws -> SignedConfigResponse

    /// Scoped variant for blocks with `wantPinsFor(...)`. Default: ``fetchSignedConfig(currentVersion:)``.
    func fetchScopedSignedConfig(currentVersion: Int, hosts: [String]?, deviceId: String?) async throws -> SignedConfigResponse
}

extension SignedConfigSource {
    public func fetchScopedSignedConfig(
        currentVersion: Int,
        hosts: [String]?,
        deviceId: String?
    ) async throws -> SignedConfigResponse {
        try await fetchSignedConfig(currentVersion: currentVersion)
    }
}
