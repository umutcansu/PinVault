import Foundation
import Security

/// Pin matching up the served certificate chain.
///
/// The leaf's key is checked first, as always. A pin may also name an issuer —
/// an intermediate or root CA certificate — so a host keeps working when its
/// leaf is renewed with a new key by the same CA.
///
/// The library does no CA validation (self-signed certificates are fine), so an
/// issuer pin only counts when the leaf really chains to that issuer: the path
/// from the leaf up to the pinned certificate is validated with the pinned
/// certificate as the sole trust anchor (signatures, validity, CA constraints).
/// Without that check an attacker could append the genuine intermediate to a
/// forged leaf and pass.
///
/// iOS: the path is validated by `SecTrust` with the basic X.509 policy, the
/// pinned certificate as the only anchor (`SecTrustSetAnchorCertificatesOnly`),
/// no network fetch, no revocation check (pins replace revocation here as they
/// replace CA trust; a lookup would also fail offline and for private CAs), at
/// the library clock. The path `SecTrust` built must then be exactly
/// `chain[0...anchor]` — the JDK's `CertPathValidator` validates the given
/// order and nothing else, and Apple's path builder may otherwise skip a
/// certificate or take one from the keychain.
enum ChainPinMatcher {

    /// The pin in `accepted` that `chain` satisfies at `now`, or nil.
    static func match(_ chain: [X509Certificate], accepted: Set<String>, now: Date) -> String? {
        guard let leaf = chain.first else { return nil }
        let leafPin = leaf.spkiPin
        if accepted.contains(leafPin) { return leafPin }
        for anchor in chain.indices.dropFirst() {
            let pin = chain[anchor].spkiPin
            if accepted.contains(pin), chainsTo(chain, anchor, now: now) { return pin }
        }
        return nil
    }

    /// True when `leaf` is issued for `hostname`: a `subjectAltName` matches it
    /// (a DNS name with RFC 6125 single-label wildcards, or an IP address
    /// literal). Same rules as OkHttp's own verifier. An empty host never matches.
    static func leafNamesHost(_ leaf: X509Certificate, _ hostname: String) -> Bool {
        guard !hostname.isEmpty else { return false }
        return HostnameVerifier.verify(hostname, leaf)
    }

    /// True when `chain[0]` chains through `chain[1..<anchor]` to `chain[anchor]` at `now`.
    static func chainsTo(_ chain: [X509Certificate], _ anchor: Int, now: Date) -> Bool {
        guard anchor > 0, anchor < chain.count else { return false }
        // The JDK does not check a trust anchor's validity; the Kotlin code does it itself.
        guard chain[anchor].isValid(at: now) else { return false }
        let path = chain[0..<anchor].compactMap { $0.secCertificate() }
        guard path.count == anchor, let anchorCert = chain[anchor].secCertificate() else { return false }

        var trust: SecTrust?
        guard SecTrustCreateWithCertificates(path as CFArray, SecPolicyCreateBasicX509(), &trust) == errSecSuccess,
              let trust else { return false }
        guard SecTrustSetAnchorCertificates(trust, [anchorCert] as CFArray) == errSecSuccess,
              SecTrustSetAnchorCertificatesOnly(trust, true) == errSecSuccess,
              SecTrustSetNetworkFetchAllowed(trust, false) == errSecSuccess,
              SecTrustSetVerifyDate(trust, now as CFDate) == errSecSuccess else { return false }
        guard SecTrustEvaluateWithError(trust, nil) else { return false }

        // Exactly the given path, ending at the pinned certificate.
        let built = (SecTrustCopyCertificateChain(trust) as? [SecCertificate]) ?? []
        let expected = chain[0...anchor].map(\.der)
        return built.map { SecCertificateCopyData($0) as Data } == expected
    }
}
