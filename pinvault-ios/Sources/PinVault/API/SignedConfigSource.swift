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
///
/// A NARROWED view (the answer to ``fetchScopedSignedConfig(currentVersion:hosts:deviceId:)``
/// with hosts or a device id) must name the request it answers inside the
/// signed payload: `"view": {"hosts": [canonical requested set], "deviceId": "<the id sent>"}`
/// (`deviceId` left out when none was sent). A full config carries no `view`.
/// The library refuses a narrowed view for a block that asks for the full
/// config, and a view of another request for a scoped one
/// (``PinVaultError/configViewMismatch(message:)``); a scoped block still
/// accepts a payload without `view` (a full view, or a backend that does not
/// write the field yet). See SERVER_IMPLEMENTATION_GUIDE.md.
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
