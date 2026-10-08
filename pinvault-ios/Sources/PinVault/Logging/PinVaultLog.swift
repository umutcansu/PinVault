import Foundation
import os

/// The library's logging, the counterpart of Timber.
///
/// One `os.Logger` per Kotlin class name (the category), subsystem
/// `io.github.umutcansu.pinvault`. Messages are the Kotlin texts verbatim (the
/// E2E suite greps them) and always `privacy: .public`.
///
/// ```swift
/// private let log = PinVaultLog.tag("SSLCertificateUpdater")
/// log.i("Config updated: v\(version)")
/// log.w("Pin recovery failed", error)
/// ```
///
/// `.debug` and `.info` lines are not persisted by the unified log; after
/// `PinVault.enableDebugLogging()` both are written at `.notice`, so
/// `log show` (and the E2E harness) sees them.
enum PinVaultLog {

    static let subsystem = "io.github.umutcansu.pinvault"

    private static let state = Locked(State())

    private struct State {
        var debugEnabled = false
        var tags: [String: Tag] = [:]
    }

    /// The logger for `category` (a Kotlin class name such as `"PinVault"`).
    static func tag(_ category: String) -> Tag {
        state.withLock { state in
            if let tag = state.tags[category] { return tag }
            let tag = Tag(category: category)
            state.tags[category] = tag
            return tag
        }
    }

    /// Diagnostic logging on: debug and info lines go out at `.notice`.
    static func enableDebugLogging() {
        state.withLock { $0.debugEnabled = true }
    }

    static var isDebugEnabled: Bool {
        state.withLock { $0.debugEnabled }
    }

    /// One category's logger. `d` / `i` / `w` / `e` mirror `Timber.d/i/w/e`;
    /// an error, when given, is appended on its own line (Timber appends the stack trace).
    struct Tag: Sendable {
        let category: String
        private let logger: Logger

        init(category: String) {
            self.category = category
            self.logger = Logger(subsystem: PinVaultLog.subsystem, category: category)
        }

        func d(_ message: @autoclosure () -> String, _ error: (any Error)? = nil) {
            let text = Self.compose(message(), error)
            if PinVaultLog.isDebugEnabled {
                logger.notice("\(text, privacy: .public)")
            } else {
                logger.debug("\(text, privacy: .public)")
            }
        }

        func i(_ message: @autoclosure () -> String, _ error: (any Error)? = nil) {
            let text = Self.compose(message(), error)
            if PinVaultLog.isDebugEnabled {
                logger.notice("\(text, privacy: .public)")
            } else {
                logger.info("\(text, privacy: .public)")
            }
        }

        func w(_ message: @autoclosure () -> String, _ error: (any Error)? = nil) {
            let text = Self.compose(message(), error)
            logger.warning("\(text, privacy: .public)")
        }

        func e(_ message: @autoclosure () -> String, _ error: (any Error)? = nil) {
            let text = Self.compose(message(), error)
            logger.error("\(text, privacy: .public)")
        }

        private static func compose(_ message: String, _ error: (any Error)?) -> String {
            guard let error else { return message }
            return message + "\n" + String(describing: error)
        }
    }
}
