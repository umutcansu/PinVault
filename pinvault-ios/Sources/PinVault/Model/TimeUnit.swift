import Foundation

/// The counterpart of `java.util.concurrent.TimeUnit` for the builder methods
/// that take an amount and a unit (`attestationInterval(2, .minutes)`).
public enum TimeUnit: String, Sendable, Equatable, Hashable, CaseIterable, Codable {
    case nanoseconds = "NANOSECONDS"
    case microseconds = "MICROSECONDS"
    case milliseconds = "MILLISECONDS"
    case seconds = "SECONDS"
    case minutes = "MINUTES"
    case hours = "HOURS"
    case days = "DAYS"

    /// `amount` of this unit in milliseconds, saturating like `TimeUnit.toMillis`.
    public func toMillis(_ amount: Int64) -> Int64 {
        switch self {
        case .nanoseconds: return amount / 1_000_000
        case .microseconds: return amount / 1_000
        case .milliseconds: return amount
        case .seconds: return Self.scale(amount, 1_000)
        case .minutes: return Self.scale(amount, 60_000)
        case .hours: return Self.scale(amount, 3_600_000)
        case .days: return Self.scale(amount, 86_400_000)
        }
    }

    /// `amount` of this unit in seconds (truncated), saturating.
    public func toSeconds(_ amount: Int64) -> Int64 {
        toMillis(amount) / 1_000
    }

    private static func scale(_ amount: Int64, _ factor: Int64) -> Int64 {
        let (result, overflow) = amount.multipliedReportingOverflow(by: factor)
        if overflow { return amount < 0 ? Int64.min : Int64.max }
        return result
    }
}
