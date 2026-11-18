import Foundation

/// The moment a config stops being usable: its `expiresAt` plus the
/// `expiredConfigGrace`. Every expiry check goes through ``deadline(_:_:)``,
/// which saturates: an app asking for a huge grace (`Int64.max` ms) must get
/// "never", not an `Int64` overflow trap. A ``PinVaultConfig`` can be built
/// without the builder, so the value is not trusted to be small.
enum ConfigExpiry {

    static func deadline(_ expiresAt: Int64, _ graceMs: Int64) -> Int64 {
        let (sum, overflow) = expiresAt.addingReportingOverflow(graceMs)
        guard overflow else { return sum }
        return graceMs > 0 ? .max : .min
    }
}
