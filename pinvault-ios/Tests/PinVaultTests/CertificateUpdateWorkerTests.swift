import Foundation
import XCTest
@testable import PinVault

/// Port of CertificateUpdateWorkerTest, plus the scheduler that runs it
/// (WorkManager's part on Android): states, retries, replacement, the run-now hook.
final class CertificateUpdateWorkerTests: XCTestCase {

    /// The periodic job's view of PinVault (the Kotlin test's `mockkObject(PinVault)`).
    final class FakeTarget: PeriodicWorkTarget, @unchecked Sendable {
        let update = Locked(UpdateResult.alreadyCurrent)
        let calls = Locked<[String]>([])
        let notified = Locked<[UpdateResult]>([])

        func updateNow() async -> UpdateResult {
            calls.withLock { $0.append("updateNow") }
            return update.get()
        }
        func notifyUpdateResult(_ result: UpdateResult) async { notified.withLock { $0.append(result) } }
        func updateOtherConfigApis() async { calls.withLock { $0.append("updateOtherConfigApis") } }
        func syncAllFiles() async -> [String: VaultFileResult] {
            calls.withLock { $0.append("syncAllFiles") }
            return [:]
        }
        func wipeStaleVaultFiles() async { calls.withLock { $0.append("wipeStaleVaultFiles") } }
        func pickUpPendingEnrollments() async { calls.withLock { $0.append("pickUpPendingEnrollments") } }
        func renewClientCertsIfNeeded() async { calls.withLock { $0.append("renewClientCertsIfNeeded") } }
        func attestAll() async { calls.withLock { $0.append("attestAll") } }
    }

    private let target = FakeTarget()

    private func doWork(_ runAttemptCount: Int = 0) async -> CertificateUpdateWorker.Result {
        await CertificateUpdateWorker.doWork(target, runAttemptCount: runAttemptCount)
    }

    // MARK: The worker

    func testSuccessOnUpdated() async {
        target.update.set(.updated(newVersion: 5))
        let result = await doWork()
        XCTAssertEqual(result, .success)
    }

    func testSuccessOnAlreadyCurrent() async {
        target.update.set(.alreadyCurrent)
        let result = await doWork()
        XCTAssertEqual(result, .success)
    }

    func testRetryOnFailedWhenTheAttemptIsBelowTheMaximum() async {
        target.update.set(.failed(reason: "network error"))
        let result = await doWork(0)
        XCTAssertEqual(result, .retry)
    }

    func testFailureOnFailedWhenTheAttemptIsAtTheMaximum() async {
        target.update.set(.failed(reason: "network error"))
        let result = await doWork(3)
        XCTAssertEqual(result, .failure)
    }

    func testRetryOnFailedAtAttempt2() async {
        target.update.set(.failed(reason: "timeout"))
        let result = await doWork(2)
        XCTAssertEqual(result, .retry)
    }

    func testTheUpdateResultIsNotifiedAndEveryStepRunsInTheKotlinOrder() async {
        target.update.set(.updated(newVersion: 10))
        _ = await doWork()
        XCTAssertEqual(target.notified.get(), [.updated(newVersion: 10)])
        XCTAssertEqual(target.calls.get(), [
            "updateNow", "updateOtherConfigApis", "syncAllFiles", "wipeStaleVaultFiles",
            "pickUpPendingEnrollments", "renewClientCertsIfNeeded", "attestAll",
        ])
    }

    // MARK: The scheduler

    private func scheduler(
        submitter: PeriodicUpdateScheduler.BackgroundSubmitter? = nil,
        sleep: @escaping @Sendable (Int64) async -> Void = { _ in try? await Task.sleep(nanoseconds: 3_600_000_000_000) },
        changes: Locked<Int> = Locked(0)
    ) -> PeriodicUpdateScheduler {
        let target = self.target
        return PeriodicUpdateScheduler(
            work: { attempts in await CertificateUpdateWorker.doWork(target, runAttemptCount: attempts) },
            onChange: { changes.withLock { $0 += 1 } },
            backgroundSubmitter: { submitter },
            sleep: sleep
        )
    }

    func testANewScheduleRunsTheJobOnceRightAwayAndIsThenEnqueued() async throws {
        let changes = Locked(0)
        let scheduler = scheduler(changes: changes)
        XCTAssertTrue(scheduler.schedule(intervalMinutes: 15))

        let ran = await eventually { self.target.notified.get().count == 1 }
        XCTAssertTrue(ran, "a new WorkManager periodic job runs as soon as it is enqueued")
        let enqueued = await eventually { scheduler.tasks().first?.state == .enqueued && changes.get() >= 3 }
        XCTAssertTrue(enqueued)
        let tasks = scheduler.tasks()
        XCTAssertEqual(tasks.count, 1)
        XCTAssertEqual(tasks[0].runAttemptCount, 0)
        XCTAssertEqual(UUID(uuidString: tasks[0].id)?.uuidString.lowercased(), tasks[0].id)
        scheduler.cancel()
    }

    func testCancelLeavesNothingEnqueuedOrRunningAndScheduleBringsItBack() async throws {
        let scheduler = scheduler()
        scheduler.schedule(intervalMinutes: 15)
        _ = await eventually { scheduler.tasks().first?.state == .enqueued && self.target.notified.get().count == 1 }
        scheduler.cancel()
        XCTAssertEqual(scheduler.tasks().map(\.state), [.cancelled])
        XCTAssertFalse(scheduler.isScheduled)

        scheduler.schedule(intervalMinutes: 15)
        XCTAssertEqual(Set(scheduler.tasks().map(\.state)).subtracting([.cancelled]).isEmpty, false)
        XCTAssertTrue(scheduler.tasks().contains { [.enqueued, .running].contains($0.state) })
        scheduler.cancel()
    }

    func testANewScheduleReplacesThePreviousOne() async throws {
        let scheduler = scheduler()
        scheduler.schedule(intervalMinutes: 15)
        let first = try XCTUnwrap(scheduler.tasks().last?.id)
        scheduler.schedule(intervalMinutes: 60)
        let tasks = scheduler.tasks()
        XCTAssertEqual(tasks.count, 2)
        XCTAssertEqual(tasks[0].id, first)
        XCTAssertEqual(tasks[0].state, .cancelled)
        XCTAssertNotEqual(tasks[1].id, first)
        XCTAssertNotEqual(tasks[1].state, .cancelled)
        scheduler.cancel()
        for _ in 0..<5 { scheduler.schedule(intervalMinutes: 15) }
        XCTAssertEqual(scheduler.tasks().count, PeriodicUpdateScheduler.historyLimit + 1, "cancelled entries are pruned")
        scheduler.cancel()
    }

    func testAFailedRunIsRetriedWithBackoffAndCountsItsAttempts() async throws {
        target.update.set(.failed(reason: "offline"))
        let waits = Locked<[Int64]>([])
        let scheduler = scheduler(sleep: { ms in
            waits.withLock { $0.append(ms) }
            try? await Task.sleep(nanoseconds: 5_000_000)
        })
        scheduler.schedule(intervalMinutes: 15)
        let retried = await eventually { waits.get().count >= 3 }
        XCTAssertTrue(retried)
        scheduler.cancel()
        // 30 s, 60 s, 120 s … never longer than the interval.
        XCTAssertEqual(Array(waits.get().prefix(3)), [30_000, 60_000, 120_000])
        XCTAssertGreaterThanOrEqual(target.notified.get().count, 3)
    }

    func testRunNowRunsTheScheduledJobAndNothingWithoutOne() async throws {
        let scheduler = scheduler()
        await scheduler.runNow()
        XCTAssertTrue(target.notified.get().isEmpty, "no job scheduled: nothing to run (cmd jobscheduler run -f)")

        scheduler.schedule(intervalMinutes: 15)
        _ = await eventually { self.target.notified.get().count == 1 }
        await scheduler.runNow()
        XCTAssertEqual(target.notified.get().count, 2)
        XCTAssertEqual(scheduler.tasks().last?.state, .enqueued)
        scheduler.cancel()
    }

    func testWhereBackgroundTasksAcceptTheRequestTheyTakeOver() async throws {
        let submitted = Locked<[Date]>([])
        let cancelled = Locked(0)
        let submitter = PeriodicUpdateScheduler.BackgroundSubmitter(
            submit: { date in submitted.withLock { $0.append(date) } },
            cancel: { cancelled.withLock { $0 += 1 } }
        )
        let scheduler = scheduler(submitter: submitter)
        scheduler.schedule(intervalMinutes: 15)
        XCTAssertEqual(submitted.get().count, 1)
        XCTAssertEqual(submitted.get()[0].timeIntervalSinceNow, 900, accuracy: 5)
        _ = await eventually { self.target.notified.get().count == 1 }

        // A background launch submits the next request, then runs.
        let succeeded = await scheduler.runFromBackground()
        XCTAssertTrue(succeeded)
        XCTAssertEqual(submitted.get().count, 2)
        XCTAssertEqual(target.notified.get().count, 2)

        scheduler.cancel()
        XCTAssertEqual(cancelled.get(), 1)
    }

    func testWhereBackgroundTasksRefuseTheInProcessSchedulerRuns() async throws {
        struct Unavailable: Error {}
        let submitter = PeriodicUpdateScheduler.BackgroundSubmitter(submit: { _ in throw Unavailable() }, cancel: {})
        let scheduler = scheduler(submitter: submitter)
        XCTAssertTrue(scheduler.schedule(intervalMinutes: 15))
        let ran = await eventually { self.target.notified.get().count == 1 }
        XCTAssertTrue(ran)
        scheduler.cancel()
    }
}
