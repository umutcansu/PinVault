import Foundation
#if canImport(BackgroundTasks) && os(iOS)
import BackgroundTasks
#endif

/// Schedules the periodic certificate update (the WorkManager periodic job of
/// Android, unique work `ssl_cert_update`, policy REPLACE).
///
/// On a device the job is a `BGAppRefreshTaskRequest` with
/// ``PinVault/backgroundTaskIdentifier`` (the app calls
/// `PinVault.registerBackgroundTask()` at launch); every run submits the next
/// one. Where `submit` throws — always on the simulator, or without the
/// Info.plist entry or the registered handler — an in-process scheduler runs
/// the same work: a task that sleeps for the interval, runs the job, and
/// retries a failed run with backoff while the app process lives.
///
/// ``tasks()`` reports the job the way `getScheduledWorkInfo` does: ENQUEUED
/// between runs, RUNNING during one, CANCELLED after ``cancel()`` or when a new
/// schedule replaced it (kept in the list for a while, like WorkManager's
/// finished work), with the retry count of the current period.
final class PeriodicUpdateScheduler: @unchecked Sendable {

    private static let log = PinVaultLog.tag("SSLCertificateUpdater")

    /// What one run does; returns the worker's result.
    typealias Work = @Sendable (_ runAttemptCount: Int) async -> CertificateUpdateWorker.Result

    /// Submits a background request whose earliest start is the given date; throws when the platform refuses.
    struct BackgroundSubmitter: Sendable {
        let submit: @Sendable (_ earliestBegin: Date) throws -> Void
        let cancel: @Sendable () -> Void
    }

    /// The first retry waits this long, doubling after that (WorkManager's exponential backoff).
    static let backoffBaseMs: Int64 = 30_000
    /// Cancelled entries kept in ``tasks()``.
    static let historyLimit = 3

    private struct Entry {
        var info: ScheduledTaskInfo
        let intervalMs: Int64
        let inProcess: Bool
        var loop: Task<Void, Never>?
    }

    private struct State {
        var current: Entry?
        var history: [ScheduledTaskInfo] = []
    }

    private let state = Locked(State())
    /// One run at a time (the loop, a background launch, the E2E hook).
    private let runGate = AsyncGate()
    private let work: Work
    private let onChange: @Sendable () -> Void
    private let backgroundSubmitter: @Sendable () -> BackgroundSubmitter?
    private let sleep: @Sendable (_ milliseconds: Int64) async -> Void

    /// - Parameters:
    ///   - backgroundSubmitter: the BGTaskScheduler road, asked at every
    ///     schedule; nil = in-process only (tests, macOS, no registered handler).
    ///   - onChange: called whenever ``tasks()`` changes (the E2E report).
    init(
        work: @escaping Work,
        onChange: @escaping @Sendable () -> Void = {},
        backgroundSubmitter: @escaping @Sendable () -> BackgroundSubmitter? = { nil },
        sleep: @escaping @Sendable (_ milliseconds: Int64) async -> Void = { try? await Task.sleep(nanoseconds: UInt64(max($0, 0)) * 1_000_000) }
    ) {
        self.work = work
        self.onChange = onChange
        self.backgroundSubmitter = backgroundSubmitter
        self.sleep = sleep
    }

    deinit {
        state.withLock { $0.current?.loop?.cancel() }
    }

    // MARK: Scheduling

    /// Schedules the job every `intervalMinutes` (at least one), replacing the
    /// one scheduled before. Returns whether it was scheduled.
    @discardableResult
    func schedule(intervalMinutes: Int64) -> Bool {
        let intervalMs = max(intervalMinutes, 1) * 60_000
        let info = ScheduledTaskInfo(id: UUID().uuidString.lowercased(), state: .enqueued, runAttemptCount: 0)

        var inProcess = true
        if let submitter = backgroundSubmitter() {
            do {
                try submitter.submit(Date().addingTimeInterval(TimeInterval(intervalMs) / 1000))
                inProcess = false
            } catch {
                Self.log.d("BGTaskScheduler refused the request (\(error)) — the in-process scheduler runs the periodic update")
            }
        }

        let replaced = state.withLock { state -> Entry? in
            let previous = state.current
            if let previous { state.history = Self.trimmed(state.history + [Self.cancelled(previous.info)]) }
            state.current = Entry(info: info, intervalMs: intervalMs, inProcess: inProcess, loop: nil)
            return previous
        }
        replaced?.loop?.cancel()
        // A new WorkManager periodic job runs once right away; on a device the
        // background requests take over after that one.
        let loop = Task { [weak self] () -> Void in
            guard let self else { return }
            if inProcess {
                await self.runLoop(id: info.id, intervalMs: intervalMs)
            } else {
                _ = await self.runOnce(id: info.id)
            }
        }
        state.withLock { state in
            if state.current?.info.id == info.id { state.current?.loop = loop } else { loop.cancel() }
        }
        Self.log.d("Periodic certificate updates scheduled — every \(intervalMs / 60_000) minutes")
        onChange()
        return true
    }

    /// Cancels the job (its entry stays listed as CANCELLED).
    func cancel() {
        let removed = state.withLock { state -> Entry? in
            guard let current = state.current else { return nil }
            state.history = Self.trimmed(state.history + [Self.cancelled(current.info)])
            state.current = nil
            return current
        }
        removed?.loop?.cancel()
        if let removed, !removed.inProcess { backgroundSubmitter()?.cancel() }
        Self.log.d("Periodic certificate updates cancelled")
        onChange()
    }

    /// The scheduled job and the ones replaced or cancelled recently, newest last.
    func tasks() -> [ScheduledTaskInfo] {
        state.withLock { state in state.history + (state.current.map { [$0.info] } ?? []) }
    }

    /// True while a job is scheduled.
    var isScheduled: Bool { state.withLock { $0.current != nil } }

    // MARK: Running

    /// Runs the scheduled job now (`cmd jobscheduler run -f`); nothing when none is scheduled.
    func runNow() async {
        guard let id = state.withLock({ $0.current?.info.id }) else {
            Self.log.d("No periodic certificate update is scheduled — nothing to run")
            return
        }
        _ = await runOnce(id: id)
    }

    /// A background launch of the job (`BGAppRefreshTask`): the next request
    /// is submitted first, then the job runs. Returns whether it succeeded.
    func runFromBackground() async -> Bool {
        let (id, intervalMs) = state.withLock { ($0.current?.info.id, $0.current?.intervalMs) }
        if let intervalMs, let submitter = backgroundSubmitter() {
            try? submitter.submit(Date().addingTimeInterval(TimeInterval(intervalMs) / 1000))
        }
        guard let id else {
            // The process was started for the job: nothing in memory says it was scheduled.
            return await work(0) != .failure
        }
        return await runOnce(id: id) != .failure
    }

    /// The in-process schedule: the first run right away (a new WorkManager
    /// periodic job runs as soon as it is enqueued), then one per interval.
    private func runLoop(id: String, intervalMs: Int64) async {
        var delay: Int64 = 0
        while !Task.isCancelled {
            if delay > 0 { await sleep(delay) }
            if Task.isCancelled || state.withLock({ $0.current?.info.id != id }) { return }
            let result = await runOnce(id: id)
            let attempts = state.withLock { $0.current?.info.runAttemptCount ?? 0 }
            delay = result == .retry ? min(Self.backoffBaseMs << min(max(attempts - 1, 0), 20), intervalMs) : intervalMs
        }
    }

    /// One run of job `id`: RUNNING while it runs, then ENQUEUED again with the
    /// retry count (WorkManager's `runAttemptCount`: reset by a success or a failure).
    @discardableResult
    private func runOnce(id: String) async -> CertificateUpdateWorker.Result {
        await runGate.lock()
        defer { runGate.unlock() }
        guard let attempts = updateState(id, { info in
            info.state = .running
        }) else { return .failure }
        onChange()
        let result = await work(attempts)
        _ = updateState(id) { info in
            info.state = .enqueued
            info.runAttemptCount = result == .retry ? info.runAttemptCount + 1 : 0
        }
        onChange()
        return result
    }

    /// Changes job `id` while it is the current one; returns its run attempt count before the change, nil when it is not.
    private func updateState(_ id: String, _ change: (inout ScheduledTaskInfo) -> Void) -> Int? {
        state.withLock { state in
            guard var entry = state.current, entry.info.id == id else { return nil }
            let attempts = entry.info.runAttemptCount
            change(&entry.info)
            state.current = entry
            return attempts
        }
    }

    private static func cancelled(_ info: ScheduledTaskInfo) -> ScheduledTaskInfo {
        var copy = info
        copy.state = .cancelled
        return copy
    }

    private static func trimmed(_ history: [ScheduledTaskInfo]) -> [ScheduledTaskInfo] {
        Array(history.suffix(historyLimit))
    }
}

#if canImport(BackgroundTasks) && os(iOS)
extension PeriodicUpdateScheduler.BackgroundSubmitter {
    /// `BGTaskScheduler` with `identifier` (a `BGAppRefreshTaskRequest`).
    static func appRefresh(_ identifier: String) -> PeriodicUpdateScheduler.BackgroundSubmitter {
        PeriodicUpdateScheduler.BackgroundSubmitter(
            submit: { earliestBegin in
                let request = BGAppRefreshTaskRequest(identifier: identifier)
                request.earliestBeginDate = earliestBegin
                try BGTaskScheduler.shared.submit(request)
            },
            cancel: { BGTaskScheduler.shared.cancel(taskRequestWithIdentifier: identifier) }
        )
    }
}
#endif
