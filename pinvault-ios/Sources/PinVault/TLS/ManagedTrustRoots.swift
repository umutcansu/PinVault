import Foundation

/// Managed trust roots: for a host that has **no pin entry**, a chain is
/// accepted when the platform's CAs validate it **and** the chain the
/// platform validated contains a certificate whose key is one of the signed
/// config's `trustRoots` (SHA-256 of the SubjectPublicKeyInfo, Base64, the
/// same form as pins) — normally the root the platform anchored on — and the
/// leaf names the host.
///
/// This is the device trust store with the authority taken away from it:
/// a CA a user or an attacker added to the device is not in `trustRoots`,
/// so it does not count, and a root the operator stops listing stops being
/// trusted on the next config, without an app update. Hosts that have a pin
/// entry are not affected; pins stay the stricter choice.
enum ManagedTrustRoots {

    private static let log = PinVaultLog.tag("ManagedTrustRoots")

    /// The root pin of `trustRoots` that `chain` validates to for `hostname`,
    /// or the reason it does not: ``PinVaultError/managedTrustRoot(message:cause:)``
    /// when the platform refuses the chain or no validated certificate matches
    /// a listed root, ``PinVaultError/hostnameMismatch(message:cause:)`` when the
    /// leaf is not issued for `hostname`.
    static func match(
        _ chain: [X509Certificate],
        hostname: String,
        trustRoots: Set<String>,
        resolver: any TrustAnchorResolver,
        now: Date
    ) throws -> String {
        guard let leaf = chain.first else { throw PinVaultError.managedTrustRoot(message: "No server certificate provided") }
        if trustRoots.isEmpty { throw PinVaultError.managedTrustRoot(message: "The config lists no managed trust roots") }
        let validated: [X509Certificate]
        do {
            validated = try resolver.validatedChain(chain, host: hostname, at: now)
        } catch {
            throw PinVaultError.managedTrustRoot(
                message: "Managed trust roots: the platform does not trust the certificate chain for '\(hostname)': \(describe(error))",
                cause: error
            )
        }
        // The anchor (last) first: that is what the list is meant to name.
        guard let matched = validated.reversed().map(\.spkiPin).first(where: trustRoots.contains) else {
            throw PinVaultError.managedTrustRoot(
                message: "Managed trust roots: the chain for '\(hostname)' validates to a root the config does not list " +
                    "(\(trustRoots.count) listed)"
            )
        }
        if !ChainPinMatcher.leafNamesHost(leaf, hostname) {
            throw PinVaultError.hostnameMismatch(
                message: "Certificate for \(hostname) chains to a managed trust root but is not issued for \(hostname) (no matching subjectAltName)"
            )
        }
        log.d("Managed trust root matched for \(hostname) — sha256/\(matched.prefix(12))...")
        return matched
    }

    /// The message of `error` (a ``PinVaultError``'s own text, like `e.message`).
    static func describe(_ error: any Error) -> String {
        (error as? PinVaultError)?.message ?? error.localizedDescription
    }
}
