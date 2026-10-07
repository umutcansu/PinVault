import Foundation

/// The test bundle as `Bundle.module`: SwiftPM generates this accessor for
/// the package's test target; the hosted bundle copies `Fixtures` itself.
private final class HostedTestBundleToken {}

extension Bundle {
    static let module = Bundle(for: HostedTestBundleToken.self)
}
