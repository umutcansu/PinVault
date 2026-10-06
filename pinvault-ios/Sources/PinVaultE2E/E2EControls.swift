import Foundation
import os
@_spi(PinVaultE2E) import PinVault

/// The E2E control channel of the sample app (PORTING.md §8). Link this
/// product only into builds with test controls.
///
/// - Reads `Library/Caches/pinvault-e2e/control.json` (written by the harness)
///   at ``start()`` and whenever the Darwin notification
///   ``controlNotification`` is posted, and applies its clock offset and
///   redirects to the library.
/// - Runs the library's periodic job when ``runScheduledWorkNotification`` is posted.
/// - Writes `report.json` (`deviceId`, `scheduledTasks`, `updatedAt`) at start
///   and whenever it changes.
///
/// ```swift
/// let controls = E2EControls.shared
/// controls.onControl = { control in /* apply control.mode to the app's settings */ }
/// controls.start()
/// let initialMode = controls.control?.mode
/// ```
public final class E2EControls: @unchecked Sendable {

    /// The contents of `control.json`.
    public struct Control: Codable, Sendable, Equatable {
        /// Initial app mode at launch (`TLS`, `MTLS`, …), like `am start --es mode`.
        public var mode: String?
        /// Added to the library's wall clock.
        public var clockOffsetSeconds: Int64?
        /// Connection-address overrides `host:port` → `host:port`.
        public var redirects: [String: String]?

        public init(mode: String? = nil, clockOffsetSeconds: Int64? = nil, redirects: [String: String]? = nil) {
            self.mode = mode
            self.clockOffsetSeconds = clockOffsetSeconds
            self.redirects = redirects
        }
    }

    /// The contents of `report.json`.
    public struct Report: Encodable, Sendable, Equatable {
        public var deviceId: String?
        public var scheduledTasks: [ScheduledTaskInfo]
        /// Epoch ms.
        public var updatedAt: Int64

        public init(deviceId: String?, scheduledTasks: [ScheduledTaskInfo], updatedAt: Int64) {
            self.deviceId = deviceId
            self.scheduledTasks = scheduledTasks
            self.updatedAt = updatedAt
        }

        enum CodingKeys: String, CodingKey { case deviceId, scheduledTasks, updatedAt }

        public func encode(to encoder: any Encoder) throws {
            var container = encoder.container(keyedBy: CodingKeys.self)
            try container.encode(deviceId, forKey: .deviceId)   // null, not absent
            try container.encode(scheduledTasks, forKey: .scheduledTasks)
            try container.encode(updatedAt, forKey: .updatedAt)
        }
    }

    public static let defaultControlNotification = "com.example.sampleclient.e2e.control"
    public static let defaultRunScheduledWorkNotification = "com.example.sampleclient.e2e.runScheduledWork"

    /// The sample app's instance (default notification names, `Library/Caches/pinvault-e2e`).
    public static let shared = E2EControls()

    public let controlNotification: String
    public let runScheduledWorkNotification: String
    /// `<Caches>/pinvault-e2e`.
    public let directory: URL
    public var controlURL: URL { directory.appendingPathComponent("control.json") }
    public var reportURL: URL { directory.appendingPathComponent("report.json") }

    private let pinVault: PinVault
    private let lock = NSLock()
    private var started = false
    private var lastControl: Control?
    private var lastReport: Report?
    private var controlHandler: (@Sendable (Control) -> Void)?
    private let log = Logger(subsystem: "io.github.umutcansu.pinvault", category: "E2EControls")

    /// - Parameters:
    ///   - controlNotification: Darwin notification that re-reads `control.json`.
    ///   - runScheduledWorkNotification: Darwin notification that runs the periodic job.
    ///   - directory: where `control.json` / `report.json` live; nil = `<Caches>/pinvault-e2e`.
    ///   - pinVault: the library instance to control.
    public init(
        controlNotification: String = E2EControls.defaultControlNotification,
        runScheduledWorkNotification: String = E2EControls.defaultRunScheduledWorkNotification,
        directory: URL? = nil,
        pinVault: PinVault = .shared
    ) {
        self.controlNotification = controlNotification
        self.runScheduledWorkNotification = runScheduledWorkNotification
        self.directory = directory
            ?? FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask)[0].appendingPathComponent("pinvault-e2e")
        self.pinVault = pinVault
    }

    deinit {
        CFNotificationCenterRemoveEveryObserver(CFNotificationCenterGetDarwinNotifyCenter(), Unmanaged.passUnretained(self).toOpaque())
    }

    /// The last control read (nil before ``start()`` or without a file).
    public var control: Control? {
        lock.withLock { lastControl }
    }

    /// Called with every control read (at start and on each notification), after it was applied to the library.
    public var onControl: (@Sendable (Control) -> Void)? {
        get { lock.withLock { controlHandler } }
        set { lock.withLock { controlHandler = newValue } }
    }

    /// Reads and applies `control.json`, observes both notifications, and
    /// writes `report.json`. Idempotent.
    public func start() {
        let first = lock.withLock { () -> Bool in
            defer { started = true }
            return !started
        }
        guard first else { return }
        let observer = Unmanaged.passUnretained(self).toOpaque()
        let center = CFNotificationCenterGetDarwinNotifyCenter()
        for name in [controlNotification, runScheduledWorkNotification] {
            CFNotificationCenterAddObserver(center, observer, { _, observer, name, _, _ in
                guard let observer, let name else { return }
                let controls = Unmanaged<E2EControls>.fromOpaque(observer).takeUnretainedValue()
                controls.handleNotification(name.rawValue as String)
            }, name as CFString, nil, .deliverImmediately)
        }
        pinVault.e2eSetScheduledTasksObserver { [weak self] in
            guard let self else { return }
            Task { await self.writeReport() }
        }
        reloadControl()
        Task { await writeReport() }
        log.notice("E2E controls started (\(self.directory.path, privacy: .public))")
    }

    /// Stops observing the notifications.
    public func stop() {
        CFNotificationCenterRemoveEveryObserver(CFNotificationCenterGetDarwinNotifyCenter(), Unmanaged.passUnretained(self).toOpaque())
        pinVault.e2eSetScheduledTasksObserver(nil)
        lock.withLock { started = false }
    }

    /// `control.json`, or nil when it is absent or unreadable.
    public func readControl() -> Control? {
        guard let data = try? Data(contentsOf: controlURL) else { return nil }
        do {
            return try JSONDecoder().decode(Control.self, from: data)
        } catch {
            log.error("control.json is not valid: \(String(describing: error), privacy: .public)")
            return nil
        }
    }

    /// Applies a control to the library: clock offset and redirects (absent fields reset them).
    public func apply(_ control: Control) {
        pinVault.e2eSetClockOffset(seconds: control.clockOffsetSeconds ?? 0)
        pinVault.e2eSetRedirects(control.redirects ?? [:])
    }

    /// Reads `control.json`, applies it and tells ``onControl``.
    @discardableResult
    public func reloadControl() -> Control {
        let control = readControl() ?? Control()
        apply(control)
        let handler = lock.withLock { () -> (@Sendable (Control) -> Void)? in
            lastControl = control
            return controlHandler
        }
        log.notice(
            "E2E control: mode=\(control.mode ?? "-", privacy: .public) clockOffset=\(control.clockOffsetSeconds ?? 0, privacy: .public)s redirects=\(control.redirects?.count ?? 0, privacy: .public)"
        )
        handler?(control)
        return control
    }

    /// Writes `report.json` when its content changed (and always the first time).
    public func writeReport() async {
        let tasks = await pinVault.scheduledTasks()
        let deviceId = pinVault.e2eDeviceId()
        let changed = lock.withLock { () -> Bool in
            guard let last = lastReport else { return true }
            return last.deviceId != deviceId || last.scheduledTasks != tasks
        }
        guard changed else { return }
        let report = Report(deviceId: deviceId, scheduledTasks: tasks, updatedAt: Int64(Date().timeIntervalSince1970 * 1000))
        do {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.sortedKeys]
            try encoder.encode(report).write(to: reportURL, options: .atomic)
            lock.withLock { lastReport = report }
        } catch {
            log.error("report.json could not be written: \(String(describing: error), privacy: .public)")
        }
    }

    private func handleNotification(_ name: String) {
        if name == controlNotification {
            reloadControl()
            Task { await writeReport() }
        } else if name == runScheduledWorkNotification {
            Task {
                await pinVault.e2eRunPeriodicWorkNow()
                await writeReport()
            }
        }
    }
}
