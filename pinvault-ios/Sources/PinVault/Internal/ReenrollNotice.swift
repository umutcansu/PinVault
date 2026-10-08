import Foundation

/// One "re-enroll" notice per client identity.
///
/// A revoked device hears `reenroll_required` on every request until it
/// re-enrolls, and a refused renewal says it once more; the app wants to be
/// told once. A new identity (after re-enrollment) can be reported again.
final class ReenrollNotice: Sendable {

    private let notifiedFor = Locked<String?>(nil)

    init() {}

    /// True the first time it is called for `identity`, false after that.
    func claim(_ identity: String) -> Bool {
        notifiedFor.withLock { notified in
            if identity == notified { return false }
            notified = identity
            return true
        }
    }

    /// The name an identity is claimed under: its issuer and serial number.
    /// `ConfigApiClient.claimReenrollNotice` claims `"none"` when no identity is loaded.
    static func identityName(_ leaf: X509Certificate) -> String {
        "\(leaf.issuer.rfc2253)#\(Hex.encode(leaf.serialNumber))"
    }
}

/// Decides when a `reenroll_required` answer is about THIS device's identity,
/// which is the only time something on the device (its vault files, with
/// `wipeVaultFilesOnRevocation()`) is deleted because of it.
///
/// The answer is a plain `403` with a JSON body (on iOS mTLS listeners a `409`
/// with `X-PinVault-Status: 403`, which the transport turns back into the
/// 403). On a connection that presented the client certificate loaded now, it
/// is the server refusing that certificate. On any other connection — a
/// TLS-only block, a request made before enrollment, a listener that asks for
/// no certificate — the server was not looking at an identity at all, and
/// whatever made it answer that way must not be able to wipe a device: the
/// app is told, nothing more.
final class IdentityRevocation: Sendable {

    private let currentIdentity: @Sendable () -> X509Certificate?
    private let notice = ReenrollNotice()

    /// - Parameter currentIdentity: the leaf the block's SSL manager presents now, or nil.
    init(currentIdentity: @escaping @Sendable () -> X509Certificate?) {
        self.currentIdentity = currentIdentity
    }

    /// True when `presented` — what a connection showed the server — is the identity loaded now.
    func presentedCurrent(_ presented: X509Certificate?) -> Bool {
        guard let current = currentIdentity(), let presented else { return false }
        return presented.der == current.der
    }

    /// True the first time the identity loaded now is found revoked; false when none is loaded.
    func claim() -> Bool {
        guard let leaf = currentIdentity() else { return false }
        return notice.claim(ReenrollNotice.identityName(leaf))
    }

    /// A refusal that arrived on a connection showing `presented`: true when the device's files should go now.
    func refusedOnConnection(_ presented: X509Certificate?) -> Bool {
        presentedCurrent(presented) && claim()
    }
}
